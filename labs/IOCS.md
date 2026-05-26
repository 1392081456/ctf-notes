# IOC Index — Cross-Lab Indicator Reference

> Aggregated **Indicators of Compromise** for every CVE reproduced in this chapter. One row per IOC category per CVE — file hashes / URI patterns / process-creation strings / network indicators. Use this file as the lookup when triaging a hit from one of the Sigma rules or hunting queries.

The full SOC artifact set for each CVE (Sigma + Suricata + multi-SIEM hunts + reproduction steps) lives in the matching subdirectory under [`labs/`](./). This file is the **flat index** — one row per indicator — for analysts who want to pivot quickly during incident triage.

## How to read this file

| Column | Meaning |
|---|---|
| **CVE** | The vulnerability identifier (or `N/A` for the unauth-Redis class) |
| **Category** | One of `URI` / `header` / `cookie` / `body` / `process` / `file` / `network` / `string` |
| **Indicator** | The exact string, regex, or value pattern to alert on |
| **Confidence** | `HIGH` (≥ 95% TP), `MEDIUM` (paired with timing/sequence is HIGH), `LOW` (FP-prone alone, hunt only) |

## IOCs by CVE

### CVE-2016-4437 — Apache Shiro 1.x RememberMe deserialization

| Category | Indicator | Confidence |
|---|---|---|
| cookie | `rememberMe=[A-Za-z0-9+/=]{64,}` (base64 length > 64 chars) | HIGH |
| cookie | Cookie body, after base64-decode + AES-CBC-decrypt with key `kPH+bIxk5D2deZiIxcaaaA==`, starts with `\xac\xed\x00\x05` (Java serialization magic) | HIGH (very low FP) |
| process | `java` process spawns `sh` / `bash` / `nc` / `curl` / `wget` shortly after a Shiro app receives a long `rememberMe` cookie | HIGH |
| string | Class name `org.apache.commons.beanutils.BeanComparator` in JVM logs | HIGH |

### CVE-2021-44228 — Apache Log4j Log4Shell

| Category | Indicator | Confidence |
|---|---|---|
| URI / header | `(?i)jndi[\${}:.\-]*?(ldap|ldaps|rmi|dns|iiop)` in any header, query, or body | HIGH |
| URI / header | `${${lower:j}ndi:` (lowercase escape variant) | HIGH |
| URI / header | `${${::-j}ndi:` (default-value escape) | HIGH |
| network | Outbound DNS query for `*.interactsh.com`, `*.oast.fun`, `*.burpcollab.net`, `*.dnslog.cn` from a Java process host | HIGH |
| network | Outbound LDAP/LDAPS/RMI connection from a Java application server to a non-internal IP | MEDIUM |
| process | `java` process loads remote `.class` file via JNDI followed by `Runtime.exec` | HIGH |

### CVE-2022-22965 — Spring4Shell

| Category | Indicator | Confidence |
|---|---|---|
| URI / body | `(?i)class[\.%]?(2E)?module[\.%]?(2E)?class[\.%]?(2E)?loader` | HIGH |
| URI / body | `class.module.classLoader.resources.context.parent.pipeline.first` | HIGH |
| URI / body | Setting AccessLogValve properties: `pattern`, `directory`, `prefix`, `suffix`, `fileDateFormat` | HIGH |
| file | New `.jsp` file created in Tomcat webapp directory (esp. `ROOT/`) from a Java process within 5 min of a `class.module` request | HIGH |
| string | JSP body contains `Runtime.getRuntime().exec` AND `request.getParameter("cmd")` | HIGH |

### CVE-2023-46604 — Apache ActiveMQ OpenWire RCE

| Category | Indicator | Confidence |
|---|---|---|
| network | Inbound TCP to port `61616` (OpenWire) from outside the broker's expected source set | MEDIUM |
| network | OpenWire `ExceptionResponse` frame containing `org.springframework.context.support.ClassPathXmlApplicationContext` | HIGH |
| process | ActiveMQ JVM downloads XML via HTTP (`wget` / `curl` / Java URLConnection) then spawns shell | HIGH |
| string | `ClassPathXmlApplicationContext` in JVM stdout/stderr | HIGH |

### CVE-2023-38646 — Metabase pre-auth JDBC URL injection

| Category | Indicator | Confidence |
|---|---|---|
| URI | `/api/setup/validate` accessed by unauthenticated session | MEDIUM (legitimate during setup window) |
| body | `details.db.url` JSON field contains `INIT=`, `RUNSCRIPT FROM`, or `CREATE ALIAS` | HIGH |
| process | Metabase JVM spawns `sh` or `bash` | HIGH |

### CVE-2023-4450 — JimuReport FreeMarker SSTI

| Category | Indicator | Confidence |
|---|---|---|
| URI / body | `<#assign value="freemarker.template.utility.Execute"?new()>` in a request to JimuReport endpoints | HIGH |
| URI / body | `${value("id")}` or other FreeMarker `Execute` invocation pattern | HIGH |
| process | JimuReport JVM spawns shell | HIGH |

### CVE-2024-23897 — Jenkins CLI `@filename`

| Category | Indicator | Confidence |
|---|---|---|
| URI / body | Request to `/cli` containing arg starting with `@/` (e.g., `@/etc/passwd`) | HIGH |
| network | Inbound TCP to port `50000` (Jenkins CLI) from non-trusted source | MEDIUM |
| file | Read of `/var/jenkins_home/secrets.key`, `*/credentials.xml` by Jenkins user | HIGH |
| string | New admin user creation in Jenkins audit log from a previously-anonymous source | HIGH |

### CVE-2024-27198 — TeamCity authentication bypass

| Category | Indicator | Confidence |
|---|---|---|
| URI | `;[^/]+/(?:admin|app/rest)` regex hit on request path | HIGH |
| URI | Specifically `/app/rest/users;jwt=` and similar `;` path parameters before REST | HIGH |
| audit | TeamCity audit log: user_created with `SYSTEM_ADMIN` role by `system` (not a human admin) | HIGH |

### CVE-2024-36401 — GeoServer XPath injection

| Category | Indicator | Confidence |
|---|---|---|
| URI | OGC parameter (`propertyName` / `valueReference` / `expression`) containing `Runtime`, `getRuntime`, `exec(`, or `ProcessBuilder` | HIGH |
| URI | `exec(java.lang.Runtime.getRuntime(),...)` literal in propertyName | HIGH |
| process | GeoServer JVM spawns `sh` / `bash` / `id` / `whoami` / `uname` | HIGH |

### CVE-2024-4956 — Nexus Repository path traversal

| Category | Indicator | Confidence |
|---|---|---|
| URI | Path containing `..` after URI normalisation (e.g., `/%2E%2E/etc/passwd`) | HIGH |
| URI | `/repository/.*/%2E%2E/` patterns | HIGH |
| file | Successful HTTP read of files outside Nexus data directory (e.g., `/etc/shadow`, `*.key`) | HIGH |

### CVE-2024-9264 — Grafana DuckDB SQL injection

| Category | Indicator | Confidence |
|---|---|---|
| body | `read_blob(`, `shellfs`, `INSTALL ` (DuckDB extension functions) in SQL Expressions API requests | HIGH |
| URI | `/api/ds/query` with `expr` containing `read_blob` | HIGH |
| process | Grafana process spawns shell via `shellfs` extension | HIGH |

### CVE-2025-29927 — Next.js middleware authorization bypass

| Category | Indicator | Confidence |
|---|---|---|
| header | Request contains `x-middleware-subrequest:` header from an external source | HIGH (zero legit FP) |
| header | Header value matches `middleware:middleware:middleware:middleware:middleware` repetition pattern | HIGH |
| URI | Access to protected route by IP that hasn't completed authentication flow | MEDIUM |

### CVE-2025-3248 — Langflow pre-auth RCE

| Category | Indicator | Confidence |
|---|---|---|
| URI | POST to `/api/v1/validate/code` containing `@validator`, `@root_validator`, `pre=True` | HIGH |
| body | Python decorator pattern executed at parse time | HIGH |
| process | Langflow Python process spawns shell or `os.system` invocation | HIGH |

### CVE-2025-49001 — DataEase JWT bypass

| Category | Indicator | Confidence |
|---|---|---|
| header | `X-DE-TOKEN` JWT with `alg: none` or forged signature | HIGH |
| URI | Access to `/de2api/*/admin/*` endpoints with forged JWT | HIGH |

### CVE-2026-22777 — ComfyUI-Manager CRLF → config injection

| Category | Indicator | Confidence |
|---|---|---|
| URI / body | Request to ComfyUI manager config endpoints containing `\r\n` or `%0d%0a` | HIGH |
| URI / body | Subsequent request setting `security_level=weak` after CRLF | HIGH |
| process | ComfyUI process restart after config write | MEDIUM |

### CVE-2026-24061 — GNU InetUtils telnetd USER injection

| Category | Indicator | Confidence |
|---|---|---|
| network | Telnet (port 23) NEW-ENVIRON negotiation with `USER=-froot` | HIGH (zero legit FP — `-f` is a `login` flag, not a username) |
| network | Telnet session with `USER=-f<username>` pattern in environment | HIGH |
| process | `login -f <user>` invoked by telnetd | HIGH |

### CVE-2026-25253 — OpenClaw Cross-Site WebSocket Hijacking

| Category | Indicator | Confidence |
|---|---|---|
| URI | WebSocket connection to OpenClaw `gatewayUrl` parameter containing attacker-controlled origin | HIGH |
| body | Subsequent config injection: `disableSandbox=true` written via leaked token | HIGH |
| process | OpenClaw sandbox process with security disabled | HIGH |

### CVE-2026-25887 — Chartbrew MongoDB `new Function()` RCE

| Category | Indicator | Confidence |
|---|---|---|
| body | MongoDB dataset query containing `global.process.mainModule.require('child_process')` | HIGH |
| body | `Function(`, `new Function(` in dataset definition body | HIGH |
| process | Node.js Chartbrew process spawns shell | HIGH |

### CVE-2026-34197 — Apache ActiveMQ Jolokia → Spring XML RCE

| Category | Indicator | Confidence |
|---|---|---|
| URI | POST to `/api/jolokia/exec/...addNetworkConnector` with `static:(vm://...)` URI | HIGH |
| body | URI parameter starting with `static:(vm://rce?brokerConfig=xbean:http://...)` | HIGH |
| process | ActiveMQ broker downloads remote XML (Spring beans) followed by `MethodInvokingFactoryBean` invocation | HIGH |

### CVE-2026-34486 — Apache Tomcat Tribes EncryptInterceptor bypass

| Category | Indicator | Confidence |
|---|---|---|
| network | Inbound TCP to Tomcat cluster port (default 4000) from non-cluster IP | HIGH |
| network | Frame with Java serialization magic bytes `\xac\xed\x00\x05` after EncryptInterceptor decrypt failure log | HIGH |
| string | Tomcat log: "Decrypt failure" followed by deserialization stack trace | HIGH |

### CVE-2017-18349 — Fastjson 1.2.24 AutoType

| Category | Indicator | Confidence |
|---|---|---|
| body | JSON request body containing `"@type":"com.sun.rowset.JdbcRowSetImpl"` | HIGH |
| body | `"@type":"org.apache.commons.collections.functors.ChainedTransformer"` | HIGH |
| body | `"dataSourceName":"ldap://"` or `rmi://` in a JSON body | HIGH |

### CVE-2019-12725 — ZeroShell `kerbynet` command injection

| Category | Indicator | Confidence |
|---|---|---|
| URI | Request to `/cgi-bin/kerbynet` with shell metacharacters (`;`, `|`, `` ` ``, `$()`) in `Action` parameter | HIGH |
| URI | `Action=StartSessionSubmit` with non-standard `User` value | MEDIUM |
| process | `kerbynet` cgi spawns unexpected shell | HIGH |

### Redis 4.x unauthorised access → RCE

| Category | Indicator | Confidence |
|---|---|---|
| network | Inbound TCP to Redis port (default 6379) from non-allowlisted source | HIGH |
| protocol | Redis command sequence `CONFIG SET dir <path>` followed by `CONFIG SET dbfilename` followed by `SAVE` | HIGH (no benign use case for path-control writes) |
| file | New SSH `authorized_keys` written by Redis process user | HIGH |
| file | New crontab written by Redis process user | HIGH |
| file | New webshell `.jsp` / `.php` written to a webserver document root by Redis user | HIGH |

---

## Pivot table — IOC indicators across CVE families

If you see an indicator in one column, look for indicators in the other columns of the same row for confirmation:

| First sign (alert tier) | Second sign (confirms exploit) | Third sign (post-exploit) |
|---|---|---|
| Long `rememberMe` cookie (Shiro) | Java process spawns shell | New file in webapp root |
| `${jndi:` in HTTP (Log4Shell) | Outbound LDAP/DNS from Java host | Remote `.class` loaded |
| `class.module.classLoader` (Spring4Shell) | New `.jsp` in Tomcat | Webshell hit pattern |
| `/cli` with `@/` (Jenkins) | Read of `secrets.key` | New admin user |
| `;` before `/admin/` (TeamCity) | `user_created` audit event | Login from non-admin source |
| `Runtime` in `propertyName` (GeoServer) | GeoServer JVM spawns shell | `id` / `whoami` in process tree |
| `${...?new()}` (FreeMarker SSTI / JimuReport) | JimuReport JVM spawns shell | Reverse shell connection |

This is the cheat sheet during a real triage call — the alert tells you the door was tried, the second column tells you the door opened, the third column tells you what they did once inside.

## See also

- Each CVE's full reproduction + Sigma rule + Suricata signature + multi-SIEM hunt: `labs/<vendor>_<year>_<id>/writeup_en.md`
- Packaged detection content (CI-linted, MIT-licensed): [`sigma-detection-rules`](https://github.com/1392081456/sigma-detection-rules)
- Hunting query templates in 3 SIEM dialects: [`sigma-detection-rules/hunting/`](https://github.com/1392081456/sigma-detection-rules/tree/main/hunting)
- Methodology behind the rules: [blog post](https://1392081456.github.io/2026/05/26/cve-to-sigma-30min/)
