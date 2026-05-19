# ctf-notes

> In-depth writeups from public CTF challenges — pwn, reverse engineering, cryptography, web exploitation, and forensics. Focus on **methodology, exploitation traps, and lessons learned** rather than just "I got the flag".

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Language](https://img.shields.io/badge/lang-EN-blue)
![Topics](https://img.shields.io/badge/topics-pwn%20|%20reverse%20|%20crypto%20|%20web%20|%20forensics%20|%20labs-red)

## About this repo

These are reconstructed writeups from challenges I worked through on publicly hosted CTF platforms (BUUCTF, SCTF, NSSCTF, NewStarCTF, etc.). They are written as a personal technical reference and to share methodology that has been publicly documented for years.

Each writeup follows the same structure:

1. **File overview** — protections, libc version, remote endpoint
2. **Vulnerability analysis** — what's broken and why
3. **Exploitation path** — the chain of primitives
4. **Full exploit** — annotated payload script
5. **Traps / Lessons learned** — what cost me hours and what I'd do differently

## Author

Security researcher with peer-reviewed publication on adversarial ML.
DOI: [10.3778/j.issn.1002-8331.2311-0227](https://doi.org/10.3778/j.issn.1002-8331.2311-0227)
CTFtime: [@colorfulwhitez](https://ctftime.org/user/colorfulwhitez) (team APWN)

## Index

### Pwn (Binary Exploitation)

- [axb_2019_heap — format string leak + unsafe unlink → BSS self-reference](pwn/axb2019_heap.md) — glibc 2.23 / unsafe unlink / `__free_hook` hijack
- [axb_2019_brop64 — ret2libc and the libc-subversion trap](pwn/axb2019_brop64.md) — glibc version detection / Partial RELRO ret2libc
- [SCTF 2019 easy_heap — null-byte off-by-one → tcache poison → mmap shellcode](pwn/sctf2019_easy_heap.md) — glibc 2.27 / consolidation leak / RWX page

### Reverse Engineering

- [WMCTF 2020 — easy_re: unpacking a PerlApp binary](reverse/wmctf2020_easy_re.md) — PerlApp BFS resource extraction
- [SCTF 2019 — creakme: AES-CBC, Base64, and SEH self-decrypting section](reverse/sctf2019_creakme.md) — multi-layer crackme
- [Wangding Cup 2020 Qinglong — jocker: SMC and stack-pointer repair](reverse/wangdingcup2020_jocker.md) — self-modifying code analysis

### Cryptography

- [GUET-CTF 2019 — encrypt: RC4 + shifted Base64 alphabet](crypto/guetctf2019_encrypt.md) — custom encoding combinations
- [GKCTF 2021 — XOR: recovering prime factors from XOR + product](crypto/gkctf2021_xor.md) — Hensel-style lifting / product-range pruning / bit-reversal coupling
- [MRCTF 2020 Easy_RSA — factoring `n` from `φ(n)` and from `e·d`](crypto/mrctf2020_easy_rsa.md) — two-stage Vieta's reduction / small-k brute force
- [LitCTF 2025 — math: RSA `hint = (p+noise)(q+noise)` leak](crypto/litctf2025_math.md) — Pollard rho on `hint−n` to recover 40-bit noise / Vieta closing to `p, q`

### Web Exploitation

- [Drupalgeddon2 — CVE-2018-7600 render array RCE](web/drupalgeddon2_rce.md) — Drupal 8 / Form API AJAX / `#post_render` injection
- [GYCTF 2020 Ez_Express — Unicode case folding + EJS prototype pollution](web/gyctf2020_ez_express.md) — Node.js / `outputFunctionName` injection / `U+0131` filter bypass
- [Wangding Cup 2020 Xuanwu SSRFMe — Gopher → Redis webshell](web/wangdingbei2020_ssrfme.md) — SSRF / `0.0.0.0` bypass / double URL encoding
- [CISCN 2019 Dropbox — PHP Phar deserialization + POP chain](web/ciscn2019_dropbox.md) — `__call` bridge / `GIF89a` stub / `file_exists` trigger
- [DASCTF 2023 EzFlask — Python class pollution via `__globals__`](web/dasctf2023_ezflask.md) — Flask / recursive merge / `__file__` overwrite

### Forensics / Incident Response

- [OtterCTF 2018 — Name Game (memory forensics)](forensics/otterctf2018_name_game.md) — Volatility 3 `pslist` fallback / WZ record parsing / dump anchoring
- [Hecheng Cup 2021 — Traffic Analysis (boolean-blind SQLi PCAP)](forensics/hcb2021_traffic_analysis.md) — `tcp.stream` pairing / frequency cross-validation / `tshark` field extraction
- [Changcheng Cup 2024 — SnakeBackdoor (Linux trojan + custom protocol)](forensics/changcheng2024_snake_backdoor.md) — 33-layer base64+zlib unpacking / glibc `srand+rand` session key / LD_PRELOAD binary oracle
- [0x401 CTF 2025 — TECI (.NET NativeAOT trojan)](forensics/0x401_2025_teci.md) — NativeAOT string recon / RC4+XOR dual-key swap trap / length-prefix protocol parsing
- [Xuanji Supply Chain Part 2 — caterpillar / cheshire-cat / twiddledee](forensics/xuanji_sc_supply_chain_part2.md) — multi-stage supply-chain poisoning + reverse-shell backdoor IR
- [Xuanji Supply Chain Part 3 — Jenkins + Gitea CI/CD compromise](forensics/xuanji_sc_supply_chain_part3.md) — webhook hijacking / command injection / credential exfiltration
- [Tieren Triathlon 2024 Finals — APK + Tomcat + PAM backdoor (18-question full chain)](forensics/tieren_2024_apk_pam_incident.md) — JWT role forgery / Behinder per-session AES / PAM `repz cmpsb` magic password / `/tmp/.sshlog` credential exfil
- [Xuanji Lab 2025 — Cobalt Strike Traffic Analysis (11-question IR)](forensics/xuanji_2025_cs_traffic_analysis.md) — CS 4.4 stager extraction / 1768.py config parse / Docker 2375 unauth → teamserver keystore / RSA-1024 private key recovery / per-session AES traffic decrypt

### Labs (Vulnerability Reproduction)

Attacker-perspective writeups for published CVEs reproduced in **local Docker labs** (primarily vulhub). Complements the forensics chapter, which covers the defender view of the same vulnerability classes. See [`labs/README.md`](labs/README.md) for the full chapter overview and constraints.

- [Apache Shiro 1.2.4 — `rememberMe` deserialization RCE (CVE-2016-4437)](labs/shiro_550/writeup_en.md) — hardcoded AES key / CommonsBeanutils1 gadget chain / `TemplatesImpl` bytecode loading
- [Apache ActiveMQ — OpenWire deserialization RCE (CVE-2023-46604)](labs/activemq_2023_46604/writeup_en.md) — Spring `ClassPathXmlApplicationContext` gadget over OpenWire wire protocol
- [Jenkins CLI — `expandAtFiles` arbitrary file read → RCE (CVE-2024-23897)](labs/jenkins_2024_23897/writeup_en.md) — args4j `@filename` expansion / anonymous CLI / credential decryption pivot
- [Grafana — DuckDB SQL injection → RCE (CVE-2024-9264)](labs/grafana_2024_9264/writeup_en.md) — SQL Expressions API / `read_blob()` file read / `shellfs` extension command execution
- [TeamCity — Authentication bypass → admin RCE (CVE-2024-27198)](labs/teamcity_2024_27198/writeup_en.md) — Servlet path-parameter trick / unauthenticated REST API / admin account creation

---

## Full training catalog

The challenges shown above are the curated **deep writeups**. For the complete index of ~300 challenges I have worked through (covering BUUCTF, NSSCTF, GHCTF, NewStarCTF, LitCTF, and other platforms), see **[CATALOG.md](CATALOG.md)**.

## Methodology

Common patterns I document across writeups:

- **Recon discipline** — `checksec`, `file`, `strings`, `readelf -s` before opening IDA
- **Libc version awareness** — never trust default libc; verify with `strings libc.so.6 | grep release`
- **Trap documentation** — anything that cost more than 10 minutes gets a "Trap" callout for future reference
- **Methodology over flag** — the writeups privilege *why* each step works over *what* each step does

## Scope and Disclaimer

Everything documented here concerns challenges from **publicly hosted CTF events, training platforms, and isolated local Docker labs of published CVEs** (vulhub-style). CTF binaries are organizer-distributed for educational purposes; lab targets are vulhub Docker images of vendor-patched software, run on `127.0.0.1` with no remote access. Nothing in this repository is intended to be applied to real systems, third-party services, or production software. Techniques described are general reverse-engineering and exploitation methodology that has been publicly documented in academic literature and conference talks for years.

## License

[MIT](LICENSE) — feel free to learn from / reference these notes; please cite if used in derivative work.
