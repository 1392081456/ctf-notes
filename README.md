# ctf-notes

> In-depth writeups from public CTF challenges — pwn, reverse engineering, cryptography, web exploitation, and forensics. Focus on **methodology, exploitation traps, and lessons learned** rather than just "I got the flag".

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Language](https://img.shields.io/badge/lang-EN-blue)
![Topics](https://img.shields.io/badge/topics-pwn%20|%20reverse%20|%20crypto%20|%20web%20|%20forensics%20|%20labs-red)

## About this repo

This is a **defensive cybersecurity research portfolio**. It contains reconstructed writeups from challenges I worked through on publicly hosted CTF platforms (BUUCTF, SCTF, NSSCTF, NewStarCTF, etc.) and reproduction notes for published CVEs in isolated local Docker labs (vulhub). The repository serves three purposes: (1) personal technical reference; (2) training material for security analysts learning offensive-side TTPs in order to design better detection logic; (3) a public record of the methodology that backs my peer-reviewed academic work in adversarial machine learning.

Each writeup follows the same structure:

1. **File overview** — protections, libc version, remote endpoint
2. **Vulnerability analysis** — what's broken and why
3. **Exploitation path** — the chain of primitives
4. **Full exploit** — annotated payload script
5. **Traps / Lessons learned** — what cost me hours and what I'd do differently

For the `labs/` chapter specifically (CVE reproduction in vulhub Docker containers), writeups additionally include a **Defense section** covering vendor patches, Suricata/Sigma detection rules, threat-hunting queries, and IOCs — see the labs chapter for the constraint statement.

## Peer-reviewed Publication

The author of this repository has a peer-reviewed publication in *Computer Engineering and Applications* (《计算机工程与应用》, Peking University Core Journal + CSCD index):

> **Data-Free Black-Box Adversarial Attack Method Based on GAN**
> *Computer Engineering and Applications*, 2025, 61(7): 204.
> DOI: [10.3778/j.issn.1002-8331.2311-0227](https://doi.org/10.3778/j.issn.1002-8331.2311-0227)
> Article page: <http://cea.ceaj.org/CN/Y2025/V61/I7/204>

**Abstract.** Adversarial examples can make deep neural networks output wrong results with high confidence. In black-box attacks, existing alternative model training methods require all or part of the training data of the target model to achieve good attack effects, but the training data of the target model is difficult to obtain in practical applications. Therefore, this paper proposes a GAN-based data-free black-box adversarial attack method. Without the training data of the target model, the noise of mixed label information is used to generate the training samples required by the substitute model. The label information of the target model and diversified loss functions are used to make the training samples evenly distributed and contain more feature information, so that the substitute model can effectively learn the classification function of the target model. Compared with DaST and MAZE, the proposed method reduces the number of adversarial perturbations and queries by 35%–60%, while increasing the success rate of FGSM, BIM, PGD attacks on CIFAR-100, CIFAR-10, SVHN, FMNIST, MNIST datasets by 6–10 percentage points on average. In the actual application of the black-box model scenario Microsoft Azure, the method achieves more than 78% attack success rate.

**Keywords.** black-box adversarial attack; generative adversarial network; substitute training; transfer attack; deep neural network

The original article is published in Chinese; the abstract and metadata above are the journal's officially published English translation (verifiable through the DOI link). The publication evidences the author's academic standing in adversarial ML and defensive AI security research.

## Use of AI Assistants

This repository documents work produced with the assistance of large language model coding assistants (primarily Claude). The assistant is used for:

- **Reverse engineering support** — disassembling and symbolizing binaries, decoding custom VMs, identifying cryptographic primitives in obfuscated code
- **Detection engineering** — translating attack chains observed in CTF and vulhub challenges into Suricata / Sigma / YARA rules and threat-hunting queries
- **Documentation and translation** — producing English writeups from Chinese-language research notes so that methodology can be shared internationally
- **Academic literature triage** — surveying published work on adversarial ML and AI-system security

All targets analyzed in this repository are one of: (a) public CTF challenge binaries distributed by event organizers, (b) vulhub Docker images of vendor-patched CVEs run on `127.0.0.1` with no external network access, or (c) the author's own intentionally vulnerable lab VMs. **No production system, third-party service, or unauthorized target is involved at any stage.** The intent of this work is consistently defensive — understanding offensive techniques deeply enough to detect them, patch them, and write durable security controls.

## Author

CTFtime: [@colorfulwhitez](https://ctftime.org/user/colorfulwhitez) (team APWN)
Academic identity verifiable through the DOI publication record above.

## Index

### Pwn (Binary Exploitation)

- [axb_2019_heap — format string leak + unsafe unlink → BSS self-reference](pwn/axb_2019_heap.md) — glibc 2.23 / unsafe unlink / `__free_hook` hijack
- [axb_2019_brop64 — ret2libc and the libc-subversion trap](pwn/axb_2019_brop64.md) — glibc version detection / Partial RELRO ret2libc
- [SCTF 2019 easy_heap — null-byte off-by-one → tcache poison → mmap shellcode](pwn/sctf_2019_easy_heap.md) — glibc 2.27 / consolidation leak / RWX page

- [ACTF 2019 — babyheap: UAF + tcache reuse + printf %s GOT leak](pwn/actf_2019_babyheap.md) — glibc 2.27 / system@PLT pre-resolved / no libc leak needed
- [ACTF 2019 — babystack: stack pivot ret2libc](pwn/actf_2019_babystack.md) — 16-byte overflow / stack address leak / leave;ret pivot
- [CISCN 2019 — n_3: 32-bit tcache UAF + strbuf overwrite](pwn/ciscn_2019_n_3.md) — record-struct funcptr → `system("sh;#")`
- [CISCN 2019 — final_2: UAF + tcache poison → overwrite `stdin->_fileno`](pwn/ciscn_2019_final_2.md) — glibc 2.27 / I/O FILE manipulation / `dup2(flag, 666)` win primitive
- [CISCN 2019 — c_3: 9-slot UAF + selfloop tcache fill + backdoor accumulator](pwn/ciscn_2019_c_3.md) — glibc 2.27 / `dele` doesn't NULL → repeated free fills tcache via self-loops / `backdoor` as fd accumulator → `__free_hook = one_gadget`
- [CISCN 2019 — c_5: `__printf_chk` format-string leak + tcache double-free](pwn/ciscn_2019_c_5.md) — glibc 2.27 / Full RELRO + FORTIFY / 7th `%p` = `_IO_2_1_stderr_` → libc base / `__free_hook = system` + `free("/bin/sh")`
- [WUSTCTF 2020 — babyfmt: 4-stage format string + `stdout->_fileno` redirect](pwn/wustctf2020_babyfmt.md) — glibc 2.23 / `%hhn` single-shot guard bypass / pre-rewrite stdout to escape `close(1)+open(/flag)` trap
- [NPUCTF 2020 — easyheap: off-by-one overlapping ×2](pwn/npuctf_2020_easyheap.md) — leak + write primitive / `__free_hook` hijack
- [SUCTF 2018 — stack: classic ret2win backdoor](pwn/suctf_2018_stack.md) — `system("/bin/sh")` gadget / +1 stack alignment
- [HWB / 强网杯 2019 — mergeheap: merge overlap + tcache poison](pwn/hwb_2019_mergeheap.md) — glibc 2.27 / size≤0x400 forces tcache-fill leak / `merge` doesn't clear original ptrs creating overlap / `__free_hook = one_gadget` getshell
### Reverse Engineering

- [WMCTF 2020 — easy_re: unpacking a PerlApp binary](reverse/wmctf2020_easy_re.md) — PerlApp BFS resource extraction
- [SCTF 2019 — creakme: AES-CBC, Base64, and SEH self-decrypting section](reverse/sctf2019_creakme.md) — multi-layer crackme
- [Wangding Cup 2020 Qinglong — jocker: SMC and stack-pointer repair](reverse/wangdingcup2020_jocker.md) — self-modifying code analysis
- [Great Wall Cup 3rd — vvvmmm: UPX + Unicorn-embedded RISC-V VM](reverse/changcheng3_vvvmmm.md) — hardcoded-key polynomial hash drives 12 stream words XOR'd with the user input; trap is the `UC_RISCV_REG` enum offset (`0xb = X10 = a0`, not `a1`)

### Cryptography

- [GUET-CTF 2019 — encrypt: RC4 + shifted Base64 alphabet](crypto/guetctf2019_encrypt.md) — custom encoding combinations
- [GKCTF 2021 — XOR: recovering prime factors from XOR + product](crypto/gkctf2021_xor.md) — Hensel-style lifting / product-range pruning / bit-reversal coupling
- [MRCTF 2020 Easy_RSA — factoring `n` from `φ(n)` and from `e·d`](crypto/mrctf2020_easy_rsa.md) — two-stage Vieta's reduction / small-k brute force
- [LitCTF 2025 — math: RSA `hint = (p+noise)(q+noise)` leak](crypto/litctf2025_math.md) — Pollard rho on `hint−n` to recover 40-bit noise / Vieta closing to `p, q`
- [XCTF 9th Finals — Tch3s: predictable `srand(time())` seed](crypto/xctf2025_tch3s.md) — brute the Unix-timestamp seed off Test 1 plaintext, then inject the recovered key into the binary via gdb-python and call its own decrypt

- [GHCTF 2025 — baby_signin: e=4 non-coprime AMM root extraction](crypto/ghctf2025_baby_signin.md) — square root signin via AMM
- [GHCTF 2025 — EZ_Fermat: polynomial-GCD RSA factoring](crypto/ghctf2025_ez_fermat.md) — Fermat's little theorem / poly-GCD over `Z/n`
- [GHCTF 2025 — MIMT_RSA: meet-in-the-middle 36-bit composite key recovery](crypto/ghctf2025_mimt_rsa.md) — multiplicative-homomorphism MITM
- [UTCTF 2020 — basic-crypto: 4-layer encoding onion](crypto/utctf2020_basic_crypto.md) — Binary → Base64 → ROT10 → Substitution
- [Yangqibei 2025 — big_e_rsa: Eisenstein integer RSA](crypto/yangqibei2025_big_e_rsa.md) — Eisenstein primes / floating-point `d` recovery
### Web Exploitation

- [Drupalgeddon2 — CVE-2018-7600 render array RCE](web/drupalgeddon2_rce.md) — Drupal 8 / Form API AJAX / `#post_render` injection
- [GYCTF 2020 Ez_Express — Unicode case folding + EJS prototype pollution](web/gyctf2020_ez_express.md) — Node.js / `outputFunctionName` injection / `U+0131` filter bypass
- [Wangding Cup 2020 Xuanwu SSRFMe — Gopher → Redis webshell](web/wangdingbei2020_ssrfme.md) — SSRF / `0.0.0.0` bypass / double URL encoding
- [CISCN 2019 Dropbox — PHP Phar deserialization + POP chain](web/ciscn2019_dropbox.md) — `__call` bridge / `GIF89a` stub / `file_exists` trigger
- [DASCTF 2023 EzFlask — Python class pollution via `__globals__`](web/dasctf2023_ezflask.md) — Flask / recursive merge / `__file__` overwrite

- [CISCN 2019 East-South — double_secret: Flask RC4 leak + Jinja2 SSTI RCE](web/ciscn2019_double_secret.md) — debug-page RC4 / SSTI command exec
- [CISCN 2019 Finals — easyweb: `\0` quote-eating SQLi + Cookie XOR forge + log-shell](web/ciscn2019_easyweb.md) — multi-stage chain
- [GHCTF 2025 — EZ_readfile: MD5 strong collision + file read](web/ghctf2025_ez_readfile.md) — `docker-entrypoint` info disclosure
- [GHCTF 2025 — SQL: UNION injection with strict WAF](web/ghctf2025_sql.md) — direct column-name guessing bypassing all function calls
- [LitCTF 2025 — easy_file: PHP LFI + upload chain](web/litctf2025_easy_file.md) — silent WAF baseline / `<?=` short-tag upload bypass
- [LitCTF 2025 — multiverse_diary: Express prototype pollution → `isAdmin`](web/litctf2025_multiverse_diary.md) — Node.js merge pollution
- [LitCTF 2025 — nest_js: Next.js weak password + JS bundle flag leak](web/litctf2025_nest_js.md) — client-side bundle disclosure
- [LitCTF 2025 — star_wish: Jinja2 SSTI `{% %}` tag bypass](web/litctf2025_star_wish.md) — command concatenation
- [NewStarCTF 2023 — medium_sql: boolean blind injection + `%53ELECT` bypass](web/newstarctf2023_medium_sql.md) — `innodb_table_stats` fallback
- [NPUCTF 2020 — yanzhengma: saferEval regex bypass + arrow-function parameter shadowing](web/npuctf2020_yanzhengma.md) — `String → Function` prototype chain RCE
- [SWPUCTF 2025 — sql_not_just_sql: numeric injection + `multi_query` stacking + UDF RCE](web/swpuctf2025_sql_not_just_sql.md) — privilege escalation chain
- [Wangding Cup 2020 Baihu — picdown: arbitrary file read + `/proc/fd` secret recovery](web/wangdingbei2020_picdown.md) — hidden route RCE
- [Xuanwu Cup 2025 — ez_fastapi: blind SSTI memory shell + `sudo chmod` escalation](web/xuanwu2025_ez_fastapi.md) — FastAPI in-memory route hijack
- [Xuanwu Cup 2025 — jinja: Jinja2 SSTI without filters](web/xuanwu2025_jinja.md) — entry-level SSTI
- [Yangcheng Cup 2020 — break_the_wall: `eval` backdoor + function-name blacklist bypass](web/yangchengbei2020_break_the_wall.md) — flag in environment variable
### Forensics / Incident Response

- [OtterCTF 2018 — Name Game (memory forensics)](forensics/otterctf2018_name_game.md) — Volatility 3 `pslist` fallback / WZ record parsing / dump anchoring
- [Hecheng Cup 2021 — Traffic Analysis (boolean-blind SQLi PCAP)](forensics/hcb2021_traffic_analysis.md) — `tcp.stream` pairing / frequency cross-validation / `tshark` field extraction
- [Changcheng Cup 2024 — SnakeBackdoor (Linux trojan + custom protocol)](forensics/changcheng2024_snake_backdoor.md) — 33-layer base64+zlib unpacking / glibc `srand+rand` session key / LD_PRELOAD binary oracle
- [0x401 CTF 2025 — TECI (.NET NativeAOT trojan)](forensics/0x401_2025_teci.md) — NativeAOT string recon / RC4+XOR dual-key swap trap / length-prefix protocol parsing
- [Xuanji Supply Chain Part 2 — caterpillar / cheshire-cat / twiddledee](forensics/xuanji_sc_supply_chain_part2.md) — multi-stage supply-chain poisoning + reverse-shell backdoor IR
- [Xuanji Supply Chain Part 3 — Jenkins + Gitea CI/CD compromise](forensics/xuanji_sc_supply_chain_part3.md) — webhook hijacking / command injection / credential exfiltration
- [Tieren Triathlon 2024 Finals — APK + Tomcat + PAM backdoor (18-question full chain)](forensics/tieren_2024_apk_pam_incident.md) — JWT role forgery / Behinder per-session AES / PAM `repz cmpsb` magic password / `/tmp/.sshlog` credential exfil
- [Xuanji Lab 2025 — Cobalt Strike Traffic Analysis (11-question IR)](forensics/xuanji_2025_cs_traffic_analysis.md) — CS 4.4 stager extraction / 1768.py config parse / Docker 2375 unauth → teamserver keystore / RSA-1024 private key recovery / per-session AES traffic decrypt
- [0x401 CTF 2025 — FlagSyndicate (Xianji #328 / #329, 18-question IR)](forensics/0x401ctf2025_flag_syndicate.md) — VMDK NBD read-only mount / yescrypt cracking with john / ELF reverse with **AES key+IV appended to ciphertext** / base64-in-base64 payload / MySQL 8.0.36 InnoDB offline revival via Docker
- [Zhenxing Cup 2025 — Phishing Oversight (EML forensics)](forensics/zhenxing2025_phishing_oversight.md) — `X-HAS-ATTACH: no` forgery / base64 decoy that is actually the XOR key (`ctf_is_good_boy`) / docx repair from XOR-encrypted ZIP
- [Zhenxing Cup 2025 — ICS C2 (OPC UA traffic)](forensics/zhenxing2025_ics_c2.md) — OPC UA node values abused as bidirectional C2 (`REACTOR-001-SEG##` commands / `RESULT-SEG##` answers) / segmented base64 reassembly into JSON / no encryption used

- [GHCTF 2025 — mybrave: bkcrack ZipCrypto known-plaintext + PNG steganography](forensics/ghctf2025_mybrave.md) — ZIP crypto break + image stego
- [GHCTF 2025 — mypcap: Tomcat Behinder webshell AES traffic decrypt + MySQL data extraction](forensics/ghctf2025_mypcap.md) — per-session AES key recovery
- [NewStarCTF 2023 — last_traffic: boolean-blind PCAP reconstruction](forensics/newstarctf2023_last_traffic.md) — HTTP response length True/False distinction
- [Xuanji DMZ2 Ubuntu — IR: Nacos CVE-2021-29442 + UID=0 hidden backdoor `sys-update`](forensics/xuanji_dmz2_ubuntu.md) — multi-stage server triage
- [CISCN / Changcheng Cup 2024 — WinFT (Windows IR, 6-question full chain)](forensics/ciscn2024_winft.md) — VMDK NBD RO mount / C2 beacon hunt / AES-CBC side-channel / phishing decode
- [Pengcheng Cup 2025 — The Rogue Beacon (CAN-bus chassis forensic)](forensics/pengchengbei2025_rogue_beacon.md) — SocketCAN 125 / rogue ID filtering / peak-speed frame localization
- [DASCTF 2025 H1 — Webshell_Plus (Bluetooth OBEX traffic)](forensics/dasctf2025h1_webshell_plus.md) — Bluetooth H4 / OBEX file reassembly (tshark hex stitching, `--export-objects` not supported) / JPEG trailer ZIP / Windows ZIP password **GBK encoding** for `の` (`a4 ce` ≠ UTF-8 `e3 81 ae`) / grayscale PNG R-channel as UTF-8 text steganography

### Labs (Vulnerability Reproduction)

Attacker-perspective writeups for published CVEs reproduced in **local Docker labs** (primarily vulhub). Complements the forensics chapter, which covers the defender view of the same vulnerability classes. See [`labs/README.md`](labs/README.md) for the full chapter overview and constraints.

- [Apache Shiro 1.2.4 — `rememberMe` deserialization RCE (CVE-2016-4437)](labs/shiro_550/writeup_en.md) — hardcoded AES key / CommonsBeanutils1 gadget chain / `TemplatesImpl` bytecode loading
- [Apache ActiveMQ — OpenWire deserialization RCE (CVE-2023-46604)](labs/activemq_2023_46604/writeup_en.md) — Spring `ClassPathXmlApplicationContext` gadget over OpenWire wire protocol
- [Jenkins CLI — `expandAtFiles` arbitrary file read → RCE (CVE-2024-23897)](labs/jenkins_2024_23897/writeup_en.md) — args4j `@filename` expansion / anonymous CLI / credential decryption pivot
- [Grafana — DuckDB SQL injection → RCE (CVE-2024-9264)](labs/grafana_2024_9264/writeup_en.md) — SQL Expressions API / `read_blob()` file read / `shellfs` extension command execution
- [TeamCity — Authentication bypass → admin RCE (CVE-2024-27198)](labs/teamcity_2024_27198/writeup_en.md) — Servlet path-parameter trick / unauthenticated REST API / admin account creation
- [ZeroShell — `kerbynet` pre-auth command injection → root (CVE-2019-12725)](labs/zeroshell_2019_12725/writeup_en.md) — unmaintained vendor / detection-only defense (Sigma + Suricata + Splunk + Sentinel) / paired Docker reproducer + ELF IOC extractor
- [Apache ActiveMQ — Jolokia addNetworkConnector → Spring XML RCE (CVE-2026-34197)](labs/activemq_2026_34197/writeup_en.md) — `static:(vm://rce?brokerConfig=xbean:http://...)` URI chain / MethodInvokingFactoryBean / CDATA XML safety
- [GNU InetUtils — telnetd USER argument injection auth bypass (CVE-2026-24061)](labs/inetutils_2026_24061/writeup_en.md) — `USER=-froot` → `login -f` / NEW-ENVIRON telnet negotiation / direct root shell
- [Chartbrew — MongoDB dataset `new Function()` injection RCE (CVE-2026-25887)](labs/chartbrew_2026_25887/writeup_en.md) — Node.js sandbox escape / `global.process.mainModule.require('child_process')` / AST validation fix

### Misc / Special

- [2025 ZhuJian Cup — Dimensionality Reduction Strike (Peano L-System QR recovery)](forensics/zhujian2025_dimensionality_reduction.md) — 729=3⁶ Peano curve / 3-frame subpixel phase separation / turtle graphics pixel reordering

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

### Authorization and Targets

| Target class | Authorization basis |
|---|---|
| CTF challenge binaries | Distributed by competition organizers as training material; participants are explicitly authorized to analyze and exploit them |
| vulhub CVE labs | Vendor-patched vulnerabilities reproduced in local Docker containers on `127.0.0.1`; the author owns the host and the containers; no external traffic involved |
| Lab VMs | Author-owned virtual machines on author-owned hardware |

No target in this repository is a third-party production system, a service the author does not own, or a network the author has not been explicitly authorized to assess. Any reader who wishes to reproduce this work must arrange equivalent authorization (own the lab, run vulhub in isolation, or have written permission from a CTF organizer).

### Defensive Orientation

The `labs/` chapter is structured so that the **Defense** section (hardening, vendor patches, Suricata/Sigma detection rules, threat-hunting queries, IOCs, post-compromise triage) occupies the majority of each writeup. Attack reproduction steps are kept concise and serve only to justify and validate the detection logic that follows. This reflects the author's research focus: offensive understanding in service of detection engineering and incident response, not offensive capability for its own sake.

## License

[MIT](LICENSE) — feel free to learn from / reference these notes; please cite if used in derivative work.
