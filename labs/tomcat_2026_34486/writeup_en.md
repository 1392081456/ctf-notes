# CVE-2026-34486 — Tomcat Tribes EncryptInterceptor Bypass Remote Code Execution

## 1. Overview

| Field | Value |
|-------|-------|
| CVE | CVE-2026-34486 |
| Product | Apache Tomcat 9.0.116 / 10.1.53 / 11.0.20 |
| Attack Vector | Network (TCP port 4000, no auth needed) |
| Impact | Remote Code Execution via Java Deserialization |
| CVSS 3.1 | 9.8 Critical |
| Patch | 9.0.117 / 10.1.54 / 11.0.21 |
| Prerequisite | Tribes cluster enabled + EncryptInterceptor + gadget chain in classpath |

Apache Tomcat Tribes is the clustering framework that enables session replication between Tomcat instances via Java serialization. When `EncryptInterceptor` is configured, serialized messages are encrypted in transit. A regression introduced while fixing CVE-2026-29146 (Padding Oracle) causes the message processing flow to continue even when decryption fails — the raw unencrypted bytes are forwarded to the deserializer. An attacker with network access to the Tribes receiver port (default 4000) can send an unencrypted Java deserialization payload that bypasses EncryptInterceptor entirely.

## 2. Attack Chain

```
Recon: Identify Tomcat with Tribes cluster (port 4000 open)
  └─▶ Generate: ysoserial CommonsCollections6 payload (requires gadget in classpath)
      └─▶ Frame: Wrap payload in Tribes protocol data frame (poc.py)
          └─▶ Deliver: TCP connect to port 4000, send framed payload
              └─▶ Bypass: EncryptInterceptor logs "Failed to decrypt" but forwards data
                  └─▶ RCE: Deserializer processes raw payload → arbitrary command execution
```

## 3. Reproduction

### Environment

```bash
cd ~/Security/tools/vulhub/tomcat/CVE-2026-34486
docker compose up -d
# Tomcat 9.0.116 with Tribes cluster + EncryptInterceptor
# Port 8080: HTTP, Port 4000: Tribes receiver
```

### Step 2 — Send Payload via Tribes Protocol

```bash
python3 poc.py -t 127.0.0.1 -p 4000 -f payload.ser
# [*] CVE-2026-34486 Tomcat Tribes EncryptInterceptor Bypass RCE
# [*] Target: 127.0.0.1:4000  Payload file: payload.ser
# [+] Payload: 1291B  Packet: 1426B
# [+] Sent!
```

The `poc.py` wraps the serialized payload in a valid Tribes data frame (HEADER + member info + payload + FOOTER) and sends it to the Tribes receiver port.

### Step 3 — Verify Command Execution

```bash
docker exec cve-2026-34486-tomcat-1 ls -la /tmp/success
# -rw-r----- 1 root root 0 May 21 16:34 /tmp/success
```

The file exists — confirming the deserialization payload was processed and the command executed. Tomcat logs show:
```
SEVERE: Failed to decrypt message
    javax.crypto.IllegalBlockSizeException: Input length must be multiple of 16...
```

The EncryptInterceptor logged the decryption failure but the message was still forwarded to the deserializer due to the regression bug.

### Key Technical Note

ysoserial must be run with the same Java version as the target (Java 8 in this case). Running ysoserial with Java 21 produces a payload with incompatible serialization format that fails with "invalid stream header" at the target.

### Cleanup

```bash
cd ~/Security/tools/vulhub/tomcat/CVE-2026-34486
docker compose down -v
```

## 4. Lessons Learned

- **Regression from security fix**: The fix for CVE-2026-29146 (Padding Oracle) introduced a worse vulnerability — the decrypt failure path no longer aborts message processing.
- **EncryptInterceptor is not a security boundary**: It was designed for confidentiality, not as an authentication/authorization mechanism. The bypass proves it cannot be relied upon to prevent unauthorized deserialization.
- **Java deserialization remains lethal**: Any network-accessible Java deserialization endpoint with gadget chains in classpath is effectively an RCE vector.
- **Cluster ports must be firewalled**: Tribes port 4000 should never be exposed to untrusted networks.

## 5. Defense

### 5.1 Hardening

| Layer | Action |
|-------|--------|
| Application | Upgrade Tomcat to 9.0.117 / 10.1.54 / 11.0.21+ |
| Network | Firewall Tribes port (4000) — allow only cluster members |
| Classpath | Remove unnecessary gadget libraries (commons-collections 3.x) |
| Architecture | Use dedicated cluster network (VLAN/VPC) isolated from user traffic |
| Monitoring | Alert on any non-cluster-member connections to port 4000 |

### 5.2 Detection — Sigma Rules

```yaml
title: Tomcat Tribes EncryptInterceptor Bypass - Deserialization on Port 4000 (CVE-2026-34486)
id: af6g3c45-7b1e-5d5h-d4f9-2e8g0h5c1d34
status: experimental
description: >
  Detects connections to Tomcat Tribes receiver port (4000) from non-cluster
  members, indicating potential exploitation of the EncryptInterceptor bypass
  for Java deserialization RCE.
references:
  - https://www.herodevs.com/vulnerability-directory/cve-2026-34486
  - https://github.com/advisories/GHSA-69r9-qgr7-g2wj
author: Security Lab
date: 2026/04/15
modified: 2026/05/21
tags:
  - attack.initial_access
  - attack.t1190
  - attack.execution
  - attack.t1059
  - cve.2026.34486
logsource:
  category: firewall
detection:
  selection:
    dst_port: 4000
    action: allowed
  filter_cluster:
    src_ip|cidr:
      - '10.0.0.0/8'
      - '172.16.0.0/12'
      - '192.168.0.0/16'
  condition: selection and not filter_cluster
falsepositives:
  - Legitimate cluster members connecting from unexpected subnets
level: critical
```

```yaml
title: Tomcat Tribes EncryptInterceptor Decrypt Failure (CVE-2026-34486 Exploitation Indicator)
id: af6g3c45-7b1e-5d5h-d4f9-2e8g0h5c1d35
status: experimental
description: >
  Detects "Failed to decrypt message" log entries from Tomcat's
  EncryptInterceptor, which indicate an attacker sent unencrypted data
  to the Tribes port — the bypass allows this data to be deserialized.
references:
  - https://www.herodevs.com/vulnerability-directory/cve-2026-34486
author: Security Lab
date: 2026/04/15
tags:
  - attack.execution
  - attack.t1059
  - cve.2026.34486
logsource:
  product: tomcat
  service: catalina
detection:
  selection:
    message|contains: 'Failed to decrypt message'
  condition: selection
falsepositives:
  - Network corruption causing legitimate cluster messages to fail decryption
level: high
```

### 5.3 Detection — Suricata Rules

```
alert tcp any any -> $HOME_NET 4000 ( \
  msg:"CVE-2026-34486 Tomcat Tribes - Connection to Cluster Port from Non-Member"; \
  flow:to_server,established; \
  content:"FLT2002"; depth:7; \
  classtype:attempted-admin; \
  sid:2026034486; rev:1; \
  metadata:cve CVE-2026-34486, attack_target web_server, \
           mitre_tactic initial_access, mitre_technique T1190; \
  reference:cve,2026-34486; \
)

alert tcp any any -> $HOME_NET 4000 ( \
  msg:"CVE-2026-34486 Tomcat Tribes - Java Serialization Magic Bytes in Tribes Frame"; \
  flow:to_server,established; \
  content:"FLT2002"; depth:7; \
  content:"|AC ED 00 05|"; \
  classtype:web-application-attack; \
  sid:2026034487; rev:1; \
  metadata:cve CVE-2026-34486, attack_target web_server, \
           mitre_tactic execution, mitre_technique T1059; \
  reference:cve,2026-34486; \
)
```

### 5.4 IOC Table

| Type | Indicator | Context |
|------|-----------|---------|
| Network | TCP connection to port 4000 from non-cluster IP | Attack delivery |
| Protocol | Tribes frame header `FLT2002` + footer `TLF2003` | Tribes protocol markers |
| Binary | Java serialization magic bytes `AC ED 00 05` inside Tribes frame | Deserialization payload |
| Log Entry | `SEVERE: Failed to decrypt message` in catalina.out | EncryptInterceptor bypass indicator |
| Log Entry | `Unable to deserialize message` after decrypt failure | Payload reached deserializer |
| Gadget Chain | `commons-collections-3.2.1.jar` in classpath | Exploitation prerequisite |
| Software | Tomcat 9.0.116 / 10.1.53 / 11.0.20 | Vulnerable versions |
| Config | `<Cluster>` with `EncryptInterceptor` in server.xml | Vulnerable configuration |

### 5.5 SIEM Hunting Queries

**Splunk SPL — Connections to Tomcat Tribes port from non-cluster IPs:**

```spl
index=firewall OR index=network
  dest_port=4000 action=allowed
| where NOT cidrmatch("10.0.0.0/8", src_ip)
        AND NOT cidrmatch("172.16.0.0/12", src_ip)
| stats count min(_time) as first_seen max(_time) as last_seen
        values(dest_ip) as targets
        by src_ip
| where count >= 1
| sort - count
```

**Splunk SPL — Tomcat EncryptInterceptor decrypt failures (exploitation indicator):**

```spl
index=application sourcetype=tomcat:catalina
  "Failed to decrypt message"
| rex field=_raw "Tribes-Task-Receiver\[(?<channel>[^\]]+)\]"
| stats count min(_time) as first_seen max(_time) as last_seen by host, channel
| where count >= 1
| sort - count
```

**Microsoft Sentinel KQL — Non-cluster connections to Tribes port:**

```kql
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DestinationPort == 4000
| where DeviceAction == "Allow"
| where not(ipv4_is_private(SourceIP))
| summarize connection_count = count(),
            targets = make_set(DestinationIP),
            first_seen = min(TimeGenerated),
            last_seen = max(TimeGenerated)
        by SourceIP
| sort by connection_count desc
```

**Microsoft Sentinel KQL — Tomcat decrypt failure log correlation:**

```kql
Syslog
| where TimeGenerated > ago(24h)
| where ProcessName == "tomcat" or Facility == "local0"
| where SyslogMessage has "Failed to decrypt message"
| summarize failure_count = count(),
            first_seen = min(TimeGenerated),
            last_seen = max(TimeGenerated)
        by HostName
| where failure_count >= 1
| sort by failure_count desc
```

## 6. Tools & References

| Tool | Purpose |
|------|---------|
| ysoserial | Java deserialization payload generation |
| poc.py (vulhub) | Tribes protocol frame construction + delivery |
| docker / vulhub | Local vulnerable environment |

- [CyberKendra Analysis](https://www.cyberkendra.com/2026/04/apache-tomcats-security-fix-opened-door.html)
- [HeroDevs Advisory](https://www.herodevs.com/vulnerability-directory/cve-2026-34486)
- [GitHub Advisory — GHSA-69r9-qgr7-g2wj](https://github.com/advisories/GHSA-69r9-qgr7-g2wj)

## 7. Disclaimer

This reproduction was performed in an isolated Docker environment (vulhub) on localhost for educational purposes only. No production systems were targeted. The goal is to understand the vulnerability mechanism and develop effective detection/hardening strategies.
