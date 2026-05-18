# ctf-notes

> In-depth writeups from public CTF challenges — pwn, reverse engineering, cryptography, web exploitation, and forensics. Focus on **methodology, exploitation traps, and lessons learned** rather than just "I got the flag".

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Language](https://img.shields.io/badge/lang-EN-blue)
![Topics](https://img.shields.io/badge/topics-pwn%20|%20reverse%20|%20crypto%20|%20web%20|%20forensics-red)

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

### Web Exploitation

- [Drupalgeddon2 — CVE-2018-7600 render array RCE](web/drupalgeddon2_rce.md) — Drupal 8 / Form API AJAX / `#post_render` injection
- [GYCTF 2020 Ez_Express — Unicode case folding + EJS prototype pollution](web/gyctf2020_ez_express.md) — Node.js / `outputFunctionName` injection / `U+0131` filter bypass
- [Wangding Cup 2020 Xuanwu SSRFMe — Gopher → Redis webshell](web/wangdingbei2020_ssrfme.md) — SSRF / `0.0.0.0` bypass / double URL encoding
- [CISCN 2019 Dropbox — PHP Phar deserialization + POP chain](web/ciscn2019_dropbox.md) — `__call` bridge / `GIF89a` stub / `file_exists` trigger
- [DASCTF 2023 EzFlask — Python class pollution via `__globals__`](web/dasctf2023_ezflask.md) — Flask / recursive merge / `__file__` overwrite

### Forensics

- [OtterCTF 2018 — Name Game (memory forensics)](forensics/otterctf2018_name_game.md) — Volatility 3 `pslist` fallback / WZ record parsing / dump anchoring
- [Hecheng Cup 2021 — Traffic Analysis (boolean-blind SQLi PCAP)](forensics/hcb2021_traffic_analysis.md) — `tcp.stream` pairing / frequency cross-validation / `tshark` field extraction

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

Everything documented here concerns challenges from **publicly hosted CTF events and training platforms**. Every binary or service analyzed has been distributed by the organizers for educational purposes. Nothing in this repository is intended to be applied to real systems, third-party services, or production software. Techniques described are general reverse-engineering and exploitation methodology that has been publicly documented in academic literature and conference talks for years.

## License

[MIT](LICENSE) — feel free to learn from / reference these notes; please cite if used in derivative work.
