<!--
==================================================================
ctf-notes 仓库的 README 升级版
覆盖现有 ~/Security/ctf-notes/README.md
==================================================================
-->

# ctf-notes

> In-depth writeups from public CTF challenges — pwn, reverse engineering, cryptography, and web exploitation. Focus on **methodology, exploitation traps, and lessons learned** rather than just "I got the flag".

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Language](https://img.shields.io/badge/lang-EN-blue)
![Topics](https://img.shields.io/badge/topics-pwn%20|%20reverse%20|%20crypto%20|%20web-red)

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

- [axb_2019_brop64 — ret2libc and the libc-subversion trap](en/05-axb2019-brop64.md) — glibc version detection / Partial RELRO ret2libc

### Reverse Engineering

- [WMCTF 2020 — easy_re: unpacking a PerlApp binary](en/01-wmctf2020-easy_re.md) — PerlApp BFS resource extraction
- [SCTF 2019 — creakme: AES-CBC, Base64, and SEH self-decrypting section](en/03-sctf2019-creakme.md) — multi-layer crackme
- [Wangding Cup 2020 Qinglong — jocker: SMC and stack-pointer repair](en/04-wangdingcup2020-jocker.md) — self-modifying code analysis

### Cryptography

- [GUET-CTF 2019 — encrypt: RC4 + shifted Base64 alphabet](en/02-guetctf2019-encrypt.md) — custom encoding combinations

## Methodology

Common patterns I document across writeups:

- **Recon discipline** — `checksec`, `file`, `strings`, `readelf -s` before opening IDA
- **Libc version awareness** — never trust default libc; verify with `strings libc.so.6 | grep release`
- **Trap documentation** — anything that cost more than 10 minutes gets a "Trap" callout for future reference
- **Methodology > flag** — the writeups privilege _why_ each step works over _what_ each step does

## Scope and Disclaimer

Everything documented here concerns challenges from **publicly hosted CTF events and training platforms**. Every binary or service analyzed has been distributed by the organizers for educational purposes. Nothing in this repository is intended to be applied to real systems, third-party services, or production software. Techniques described are general reverse-engineering and exploitation methodology that has been publicly documented in academic literature and conference talks for years.

## License

[MIT](LICENSE) — feel free to learn from / reference these notes; please cite if used in derivative work.
