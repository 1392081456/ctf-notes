# PortSwigger File Upload Vulnerabilities 1-7 — Upload, Store, Serve, Execute

This is a consolidated walkthrough of the seven PortSwigger File Upload labs.

All labs were solved in the authorized Web Security Academy environment. The main lesson is that upload safety spans four stages: upload validation, storage, serving, and execution. A file can pass one stage and still become dangerous at another.

## 1. Overview

| # | Lab | Broken layer | Core idea |
|---|-----|--------------|-----------|
| 1 | no validation | upload and execute | upload `.php` into public avatar path |
| 2 | Content-Type bypass | client-controlled MIME | set multipart `Content-Type: image/jpeg` |
| 3 | path traversal | storage path | `filename="..%2fexploit.php"` escapes avatar directory |
| 4 | extension blacklist bypass | handler configuration | upload `.htaccess`, then execute `.l33t` |
| 5 | obfuscated extension | extension parsing | `exploit.php%00.jpg` stores as `.php` |
| 6 | polyglot upload | content validation | valid JPEG with PHP in metadata |
| 7 | race condition | validation timing | fetch file between move and unlink |

## 2. Triage model

For any upload feature, ask:

1. What does the validator check?
2. Where is the file stored?
3. Can the attacker influence the filename or path?
4. How is the file served?
5. Which layer decides whether the file is executable?
6. Is the file ever publicly reachable before validation finishes?

Those questions find most upload bugs faster than guessing extensions.

## 3. Simple validation failures

The first lab accepts a PHP file in the avatar directory and serves it from:

```http
GET /files/avatars/exploit.php
```

The second lab blocks the extension only after trusting a user-controlled multipart header:

```http
Content-Disposition: form-data; name="avatar"; filename="exploit.php"
Content-Type: image/jpeg
```

The lesson is that MIME from the request is advisory, not validation.

## 4. Path and extension confusion

The path-traversal lab stores uploaded files under an avatars directory that does not execute PHP. The filename is decoded and joined unsafely:

```http
filename="..%2fexploit.php"
```

The file lands one directory higher, where PHP execution is enabled.

The blacklist lab allows `.htaccess`. Uploading:

```apache
AddType application/x-httpd-php .l33t
```

changes Apache's handler for the directory. A second upload named `exploit.l33t` is then interpreted as PHP.

The obfuscated-extension lab uses a null-byte trick:

```http
filename="exploit.php%00.jpg"
```

One layer sees the allowed `.jpg`; another stores or interprets only `exploit.php`.

## 5. Polyglot content

The content-validation lab requires a real image. The payload is placed in JPEG metadata:

```bash
exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" input.jpg -o polyglot.php
```

The file remains parseable as an image, but the PHP interpreter still executes the PHP block when it is served as `.php`.

## 6. Validation timing

The race-condition lab shows why validation must happen before public placement:

```php
move_uploaded_file($_FILES["avatar"]["tmp_name"], $target_file);
if (checkViruses($target_file) && checkFileType($target_file)) {
    echo "uploaded";
} else {
    unlink($target_file);
}
```

The uploaded file exists in the public directory before `checkViruses()` and `checkFileType()` finish. One request stream repeatedly uploads the file; another repeatedly requests it. One successful hit before `unlink()` is enough.

## 7. Defense and detection

Hardening:

- Store uploads outside the webroot.
- Generate server-side filenames and ignore client paths.
- Use an allowlist for extensions after full decoding and normalization.
- Validate MIME, magic bytes, and decoded image content.
- Re-encode images and strip metadata where possible.
- Disable script execution and `.htaccess` overrides in upload directories.
- Validate in a private quarantine location, then atomically move approved files.

Detection:

- Uploads with `.php`, `.phtml`, `.phar`, `.htaccess`, double extensions, `%00`, `../`, or encoded slashes.
- Mismatch between extension, multipart MIME, and magic bytes.
- PHP tags or filesystem functions inside image metadata.
- Immediate high-rate GETs for a just-uploaded filename.
- Executable responses from an upload directory.
- `.htaccess` content containing `AddType` or `SetHandler`.

No lab in this series required a Collaborator/OAST channel.
