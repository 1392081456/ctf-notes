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

## Companion repository — rules packaged for distribution

The Sigma and Suricata content embedded in each writeup below is also packaged as a stand-alone, CI-linted distribution:

➜ [**`1392081456/sigma-detection-rules`**](https://github.com/1392081456/sigma-detection-rules) — 30 Sigma rules + 24 Suricata signatures + 6-CVE threat-hunting query bundle (3 SIEM dialects each). Regenerable from this directory via [`scripts/extract_rules.py`](https://github.com/1392081456/sigma-detection-rules/blob/main/scripts/extract_rules.py).

If you only want to deploy the detection content (not read the writeups), pull that repo instead.

## IOC index across all 23 CVEs

➜ [**`IOCS.md`**](IOCS.md) — flat indicator table for every CVE in this chapter (cookie patterns, URI patterns, body strings, process-creation signatures, network indicators), tagged with confidence levels. Used as the lookup during incident triage when an alert from one of the Sigma rules fires.

## Index

| Lab | CVE | Class | Difficulty | Date |
|---|---|---|---|---|
| [Apache Shiro 1.2.4 — `rememberMe` deserialization RCE](shiro_550/writeup_en.md) | CVE-2016-4437 | Java deserialization (hardcoded key) | ★★☆☆☆ | 2026-05-16 |
| [Log4j — JNDI Lookup RCE (Log4Shell)](log4j_2021_44228/writeup_en.md) | CVE-2021-44228 | JNDI injection → remote class loading | ★★☆☆☆ | 2026-05-21 |
| [Spring Framework — Spring4Shell RCE](spring_2022_22965/writeup_en.md) | CVE-2022-22965 | ClassLoader manipulation via data binding | ★★☆☆☆ | 2026-05-21 |
| [Apache ActiveMQ — OpenWire deserialization RCE](activemq_2023_46604/writeup_en.md) | CVE-2023-46604 | Java deserialization (non-HTTP protocol) | ★★★☆☆ | 2026-05-19 |
| [Metabase — Pre-Auth JDBC URL injection → RCE](metabase_2023_38646/writeup_en.md) | CVE-2023-38646 | JDBC URL injection (H2 INIT parameter) | ★★★☆☆ | 2026-05-19 |
| [JimuReport — FreeMarker SSTI → RCE](jimureport_2023_4450/writeup_en.md) | CVE-2023-4450 | Server-Side Template Injection (FreeMarker) | ★★☆☆☆ | 2026-05-19 |
| [GeoServer — XPath property name evaluation → RCE](geoserver_2024_36401/writeup_en.md) | CVE-2024-36401 | XPath/EL injection in OGC request parameters | ★★☆☆☆ | 2026-05-19 |
| [Grafana — DuckDB SQL injection → RCE](grafana_2024_9264/writeup_en.md) | CVE-2024-9264 | SQL injection via DuckDB engine (shellfs extension) | ★★★☆☆ | 2026-05-19 |
| [TeamCity — Authentication bypass → admin account creation](teamcity_2024_27198/writeup_en.md) | CVE-2024-27198 | Auth bypass (path parameter trick) → REST API abuse | ★★★☆☆ | 2026-05-19 |
| [Nexus Repository — Unauthenticated path traversal](nexus_2024_4956/writeup_en.md) | CVE-2024-4956 | Path traversal via Jetty URI normalization bug | ★★☆☆☆ | 2026-05-19 |
| [Redis 4.x Unauthorized Access → RCE](redis_4_unacc/writeup_en.md) | N/A | Unauthenticated Redis → crontab/SSH key/webshell | ★★☆☆☆ | 2026-05-21 |
| [Fastjson 1.2.24 — Deserialization RCE](fastjson_1224_rce/writeup_en.md) | N/A | Java deserialization via autoType (JNDI/TemplatesImpl) | ★★☆☆☆ | 2026-05-21 |
| [Next.js — Middleware authorization bypass](nextjs_2025_29927/writeup_en.md) | CVE-2025-29927 | Internal header abuse skips middleware auth | ★☆☆☆☆ | 2026-05-19 |
| [Langflow — Pre-Auth RCE via Python decorator exec](langflow_2025_3248/writeup_en.md) | CVE-2025-3248 | Python code validation endpoint executes decorators | ★★☆☆☆ | 2026-05-19 |
| [DataEase — JWT Signature Bypass → Admin Access](dataease_2025_49001/writeup_en.md) | CVE-2025-49001 | JWT verification exception caught but not aborted | ★★☆☆☆ | 2026-05-21 |
| [ComfyUI — CRLF Injection → Config Manipulation → RCE](comfyui_2026_22777/writeup_en.md) | CVE-2026-22777 | CRLF injection in config writer downgrades security | ★★★☆☆ | 2026-05-21 |
| [OpenClaw — Cross-Site WebSocket Hijacking → RCE](openclaw_2026_25253/writeup_en.md) | CVE-2026-25253 | CSWSH token leak → config injection → sandbox disable → RCE | ★★★★☆ | 2026-05-21 |
| [Tomcat Tribes — EncryptInterceptor Bypass → Deserialization RCE](tomcat_2026_34486/writeup_en.md) | CVE-2026-34486 | Decrypt failure not aborted → raw bytes deserialized | ★★★☆☆ | 2026-05-21 |
| [ZeroShell — `kerbynet` Pre-Auth Command Injection → Root](zeroshell_2019_12725/writeup_en.md) | CVE-2019-12725 | Command injection in `/kerbynet` CGI parameter | ★★☆☆☆ | 2026-05-22 |
| [Jenkins CLI — `expandAtFiles` Arbitrary File Read → RCE](jenkins_2024_23897/writeup_en.md) | CVE-2024-23897 | args4j `@filename` expansion / anonymous CLI | ★★★☆☆ | 2026-05-19 |
| [Apache ActiveMQ — Jolokia addNetworkConnector → Spring XML RCE](activemq_2026_34197/writeup_en.md) | CVE-2026-34197 | `static:(vm://...?brokerConfig=xbean:http://)` URI chain | ★★★☆☆ | 2026-05-24 |
| [GNU InetUtils — telnetd USER Argument Injection Auth Bypass](inetutils_2026_24061/writeup_en.md) | CVE-2026-24061 | `USER=-froot` → `login -f` → root shell | ★☆☆☆☆ | 2026-05-24 |
| [Chartbrew — MongoDB Dataset `new Function()` Injection RCE](chartbrew_2026_25887/writeup_en.md) | CVE-2026-25887 | Node.js sandbox escape via `require('child_process')` | ★★☆☆☆ | 2026-05-24 |

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
