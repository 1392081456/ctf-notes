# Labs — Vulnerability Reproduction Writeups

> Attacker-perspective writeups for N-day vulnerabilities reproduced in **isolated local Docker labs** (primarily [vulhub](https://github.com/vulhub/vulhub)). Complements the [`forensics/`](../forensics/) chapter, which documents the **defender** view of similar incidents.

## Why a separate chapter?

The other chapters of this repo (`pwn`, `reverse`, `crypto`, `web`, `forensics`) cover CTF challenges — synthetic puzzles with a single intended path. **Labs** cover real-world CVEs reproduced against the affected software stacks themselves. Both are educational and use only publicly distributed materials, but the framing differs:

| Aspect | CTF writeups | Lab writeups |
|---|---|---|
| Target | Organizer-distributed challenge binary | vulhub Docker image of the affected software |
| Vulnerability | Intentional, designed by the author | Real historical CVE |
| Goal | Get the flag | Reproduce the published exploit chain, understand each primitive |
| Defense section | Optional | Required — every lab ends with mitigation guidance |

## Scope and constraints

- Every lab environment is **local Docker only** (`docker compose up` on `127.0.0.1`). No remote targets, no production systems.
- All CVEs documented here are **published, patched, and have been public for years** — these are reconstruction exercises against software whose vendors have shipped fixes long ago.
- Every writeup ends with a **Mitigation** section: knowing how a class of bug works is the first step to writing the detection or hardening that catches the next one.

## Index

| Lab | CVE | Class | Difficulty | Date |
|---|---|---|---|---|
| [Apache Shiro 1.2.4 — `rememberMe` deserialization RCE](shiro_550/writeup_en.md) | CVE-2016-4437 | Java deserialization (hardcoded key) | ★★☆☆☆ | 2026-05-16 |
| [Apache ActiveMQ — OpenWire deserialization RCE](activemq_2023_46604/writeup_en.md) 🚧 | CVE-2023-46604 | Java deserialization (non-HTTP protocol) | ★★★☆☆ | 🚧 WIP |
| [Jenkins CLI — `expandAtFiles` arbitrary file read → RCE](jenkins_2024_23897/writeup_en.md) 🚧 | CVE-2024-23897 | Arbitrary file read chained to credential decryption | ★★★☆☆ | 🚧 WIP |

## Writeup structure

Each lab follows the [`TEMPLATE.md`](TEMPLATE.md) layout:

1. **Overview** — CVE metadata, affected versions, vulnerability class
2. **Attack Chain** — one-line summary
3. **Step-by-Step Reproduction** — environment, fingerprinting, payload construction, exploitation, verification
4. **Lessons Learned** — common reproduction traps (class file version mismatches, module-system reflection blocks, etc.)
5. **Defense** (required) — three sub-sections that mirror the attack:
   - *Hardening* — vendor patch path, configuration changes, dependency trimming, runtime sandboxing
   - *Detection* — WAF/IDS signatures, log anomalies, behavioral rules (Falco/Sysmon), with a concrete example
   - *Threat Hunting* — file/memory/log/network IOCs to find a successful breach after the fact
6. **Tools & References** — vulhub link, upstream advisory, CVE/NVD page

## Disclaimer

Every lab in this directory targets a **local Docker container running publicly distributed vulnerable software** for the purpose of understanding the vulnerability mechanics. No third-party or production systems are involved. Techniques are reconstruction exercises based on advisories, public PoCs, and academic literature that has been available for years. Use this material only against systems you own or are explicitly authorized to test.
