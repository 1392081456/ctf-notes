# PortSwigger Information Disclosure 1-5 — Leaks Are Missing Exploit Parameters

This is a consolidated walkthrough of the five PortSwigger Information Disclosure labs.

All labs were solved in the authorized Web Security Academy environment. The main lesson is that an information leak becomes dangerous when it supplies the missing parameter for the next step: a version, secret, source path, header name, or password.

## 1. Overview

| # | Lab | Leak surface | Useful data |
|---|-----|--------------|-------------|
| 1 | error messages | verbose stack trace | Apache Struts 2 version `2 2.3.31` |
| 2 | debug page | HTML comment to `phpinfo.php` | `SECRET_KEY` environment variable |
| 3 | backup files | `robots.txt` and `/backup` | hard-coded database password |
| 4 | auth bypass via disclosure | `TRACE /admin` | `X-Custom-IP-Authorization` header name |
| 5 | version control history | exposed `/.git` | old administrator password in a diff |

## 2. Triage model

A fast information-disclosure pass checks:

- error behavior with wrong types and missing parameters;
- HTML comments, robots, sitemaps, and directory indexes;
- debug pages and environment dumps;
- backup extensions such as `.bak`, `.old`, and `~`;
- HTTP methods such as `TRACE`;
- exposed VCS metadata: `.git`, `.svn`, `.hg`.

The goal is not just to collect data. The goal is to ask what the leaked data unlocks.

## 3. Error messages and debug pages

In the first lab, the product endpoint expects an integer:

```http
GET /product?productId=1
```

Sending a string triggers a full stack trace:

```http
GET /product?productId="example"
```

The trace reveals `Apache Struts 2 2.3.31`, which is the solution value.

The debug-page lab starts from an HTML comment that links to:

```text
/cgi-bin/phpinfo.php
```

The page exposes environment variables, including `SECRET_KEY`. In real systems, this class of leak often enables signed-cookie forgery, token validation bypass, or secondary source-code access.

## 4. Backup source and custom headers

The backup-files lab uses `robots.txt` as the first clue:

```text
/backup
```

The backup directory exposes `ProductTemplate.java.bak`, and the source contains a hard-coded Postgres password. Robots is not access control, and backup files are source disclosure.

The auth-bypass lab is more subtle. `/admin` is protected unless the request appears local. A `TRACE` request echoes the front-end-added internal header:

```http
X-Custom-IP-Authorization: <client-ip>
```

Adding the same header with localhost bypasses the check:

```http
X-Custom-IP-Authorization: 127.0.0.1
```

The issue is not just that TRACE is enabled. The deeper bug is trusting a client-controllable header for a local-origin decision.

## 5. Git history is still public data

The final lab exposes:

```text
/.git/
```

After downloading the metadata, `git log` reveals a commit called "Remove admin password from config". The current file uses an environment variable, but the old password is still visible in the diff.

Removing a secret from the current tree is not remediation. Rotate the secret and purge the history if that history was public.

## 6. Defense and detection

Hardening:

- Return generic production errors and keep stack traces in internal logs.
- Disable public debug pages, phpinfo, directory indexes, and source backups.
- Treat robots and sitemap entries as public.
- Disable TRACE unless there is a specific controlled need.
- Strip internal trust headers at the edge and set them only from trusted proxies.
- Keep VCS metadata out of the webroot.
- Rotate any secret that appeared in a public response or repository history.

Detection:

- Requests with malformed parameter types followed by stack-trace responses.
- Access to `/robots.txt`, `/backup`, `*.bak`, `*.old`, `*~`, or `/cgi-bin/phpinfo.php`.
- `TRACE` requests.
- Requests for `.git/HEAD`, `.git/config`, and `.git/objects/`.
- External clients setting internal headers such as `X-Custom-IP-Authorization`.

No lab in this series required a Collaborator/OAST channel.
