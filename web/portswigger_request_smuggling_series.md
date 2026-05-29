# PortSwigger HTTP Request Smuggling 1-22 — Parser Boundaries and Desync

This is a consolidated walkthrough of the 22 PortSwigger HTTP request smuggling labs.

All labs were solved in the authorized Web Security Academy environment. The durable lesson is that request smuggling is not a single header trick. It is a parser disagreement: two components look at the same bytes and disagree about where one request ends and the next begins.

## 1. Overview

| # | Lab | Bug class | Core idea |
|---|-----|-----------|-----------|
| 1 | confirming CL.TE via differential responses | CL.TE | smuggle `GET /404` and watch the next request receive 404 |
| 2 | confirming TE.CL via differential responses | TE.CL | `Content-length: 4` leaves `/404` queued on the back end |
| 3 | bypass front-end controls, CL.TE | CL.TE | reach `/admin` with `Host: localhost` |
| 4 | bypass front-end controls, TE.CL | TE.CL | chunk body contains the admin deletion request |
| 5 | reveal front-end request rewriting | CL.TE | reflect the front-end's hidden client-IP header |
| 6 | capture other users' requests | CL.TE | store the next user's request as a comment body |
| 7 | deliver reflected XSS | CL.TE + XSS | queue a reflected `User-Agent` XSS response for the victim |
| 8 | response queue poisoning via H2.TE | H2 downgrade | poison the back-end response queue and capture admin session |
| 9 | H2.CL request smuggling | H2 downgrade | `Content-Length: 0` with a body hijacks resource loading |
| 10 | H2 smuggling via CRLF injection | H2 header injection | inject `Transfer-Encoding` during downgrade |
| 11 | H2 request splitting via CRLF injection | H2 splitting | split a downgraded request and poison the response queue |
| 12 | 0.CL request smuggling | browser desync | one side sees zero body, the other consumes the following bytes |
| 13 | CL.0 request smuggling | browser desync | find an endpoint that ignores `Content-Length` |
| 14 | basic CL.TE | CL.TE | smuggle `G` so the back end sees `GPOST` |
| 15 | basic TE.CL | TE.CL | leave `GPOST` queued with `Content-length: 4` |
| 16 | obfuscated TE header | TE ambiguity | duplicate TE headers trigger different parser choices |
| 17 | web cache poisoning | smuggling + cache | cache a JS resource as a redirect to the exploit server |
| 18 | web cache deception | smuggling + cache | cache the victim's account page under a static resource key |
| 19 | H2 request tunnelling access-control bypass | H2 tunnelling | leak front-end auth headers, then tunnel `/admin` |
| 20 | H2 request tunnelling cache poisoning | H2 tunnelling + cache | poison a cached response through `:path` injection |
| 21 | client-side desync | browser desync | make the victim browser desynchronize its own connection |
| 22 | pause-based request smuggling | pause-based CL.0 | pause after headers, then append the admin request |

## 2. The mental model

Every lab reduces to four questions:

1. Which component decides request boundaries from `Content-Length`?
2. Which component decides request boundaries from `Transfer-Encoding`?
3. Is the front-end-to-back-end connection reused across requests or users?
4. What impact can the queued bytes create: 404 oracle, admin access, response queue poisoning, victim request capture, XSS, or cache poisoning?

The common classes:

```text
CL.TE   front end uses Content-Length; back end uses chunked Transfer-Encoding
TE.CL   front end uses chunked Transfer-Encoding; back end uses Content-Length
H2.CL   HTTP/2 request is downgraded and an HTTP/1 Content-Length is trusted
H2.TE   HTTP/2 request is downgraded and Transfer-Encoding survives
CL.0    one endpoint ignores the declared body
0.CL    one side believes the body is zero-length; another side still consumes it
```

## 3. HTTP/1 primitives

### CL.TE

In a CL.TE chain, the front end forwards a body based on `Content-Length`, while the back end treats it as chunked. After the zero chunk, any remaining bytes become the next request prefix:

```http
POST / HTTP/1.1
Host: LAB
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

Repeating the request makes the back end parse `GPOST`, which solves the basic lab.

For differential confirmation, replace `G` with:

```http
GET /404 HTTP/1.1
X-Ignore: X
```

If the next request receives 404, the prefix was queued successfully.

### TE.CL

In TE.CL, the front end accepts a chunked body, but the back end obeys a small `Content-Length`. This leaves most of the chunk body queued:

```http
POST / HTTP/1.1
Host: LAB
Content-Type: application/x-www-form-urlencoded
Content-length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

```

The final zero chunk and trailing CRLF are part of the outer request as seen by the front end. Without them, the request is malformed before it reaches the interesting parser disagreement.

### Obfuscated Transfer-Encoding

The obfuscation lab uses duplicate headers:

```http
Transfer-Encoding: chunked
Transfer-encoding: cow
```

One component honors `chunked`; the other component rejects or ignores it and falls back to `Content-Length`.

## 4. Turning boundary control into impact

The admin bypass labs show the first useful escalation. The front end blocks `/admin`, but the back end accepts the request when it appears to come from the local trust boundary:

```http
GET /admin/delete?username=carlos HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=
```

The inner `Content-Length` is there to absorb bytes from the next real request, preventing header conflicts.

The request-rewriting lab adds one more step. The front end injects an unknown client-IP header. By smuggling a search request with an oversized body, the rewritten headers are reflected into the `search` parameter. Once the hidden `X-*-IP` header name is known, the admin request can include:

```http
X-*-IP: 127.0.0.1
```

and the delete action succeeds.

## 5. Victim-state labs

The request-capture lab smuggles a comment submission with a large body length. The next user's request is consumed as the comment body, exposing their cookie. The main tuning variable is body length: too short misses the cookie; too long produces a timeout.

The reflected-XSS lab queues a request for a blog post with a hostile `User-Agent`:

```http
User-Agent: a"/><script>alert(1)</script>
```

The victim receives the reflected response, not the attacker. This is the theme of many later labs: the attacker controls a queued request, but the impact lands on the next user or the cache.

## 6. Cache impact

Web cache poisoning uses smuggling to make a cached JavaScript resource receive a redirect influenced by `/post/next`. The exploit server hosts JavaScript at the redirected path:

```js
alert(document.cookie)
```

When the victim loads the site's tracking script, the cached redirect sends the browser to attacker-controlled JavaScript.

Web cache deception inverts the goal. The attacker smuggles:

```http
GET /my-account HTTP/1.1
X-Ignore: X
```

so that the victim's account response is stored under a static-resource cache key. The solution is to retrieve the cached response and submit the victim API key.

The operational trap is self-poisoning. Fetching the target cache key too early can cache a login redirect, 404, or harmless response before the victim request arrives.

## 7. HTTP/2 downgrade bugs

HTTP/2 does not use HTTP/1 request lines or chunked transfer coding, but front ends often downgrade H2 to HTTP/1 before forwarding upstream. The vulnerable cases preserve or synthesize dangerous HTTP/1 semantics.

H2.TE response queue poisoning sends an H2 request with:

```http
Transfer-Encoding: chunked

0

GET /x HTTP/1.1
Host: LAB

```

The back end sees an extra request, shifting the response queue. By repeatedly reading responses, the attacker can capture an admin response and reuse the session cookie to delete `carlos`.

H2.CL uses `Content-Length: 0` while still sending a body. The front end treats the request as empty; the downgraded back end receives queued bytes. In the lab, this is timed against the victim's resource import so the victim loads JavaScript from the exploit server.

The CRLF labs exploit poor sanitization during downgrade. If a header value can contain newline bytes, it can inject HTTP/1 headers:

```text
foo: bar\r\n
Transfer-Encoding: chunked
```

or split the request entirely. The same queue-poisoning impact then applies.

## 8. Request tunnelling

Request tunnelling is different from classic smuggling: the front end does not reuse the back-end connection, so there is no cross-request queue to poison. Instead, the attacker injects a second HTTP/1 request inside a single downgraded HTTP/2 request.

In the access-control lab, header-name injection is used to leak the front end's client authentication headers. Those headers are then included in a tunnelled admin request.

In the cache-poisoning lab, the `:path` pseudo-header is abused to tunnel a second request:

```text
/?cachebuster=1 HTTP/1.1
Host: LAB

GET /post?postId=1 HTTP/1.1
Foo: bar
```

Using `HEAD` lets the poisoned response be cached under the chosen key while the body comes from the tunnelled request.

## 9. Browser-powered and pause-based desync

CL.0 and 0.CL labs move the problem closer to real browsers:

- CL.0: the client sends a body, but a vulnerable endpoint ignores `Content-Length`.
- 0.CL: one side treats the request as zero-length, while another side continues consuming body bytes.

The CL.0 workflow is:

1. Probe endpoints by sending a POST with a smuggled request in the body.
2. Send a second request on the same connection.
3. If the second response matches the smuggled prefix, the endpoint ignored the body.
4. Replace the probe with the admin delete request.

Client-side desync uses the victim browser as the connection owner. The exploit page causes the browser to send one request whose body is ignored, then a follow-up request on the same connection. The server-side desync leaks the victim cookie.

Pause-based smuggling adds a timing primitive. Send headers with a declared body length, pause long enough for the back-end body read to time out while keeping the connection open, then send the smuggled body. The lab uses a redirecting Apache directory endpoint and then appends the admin request.

## 10. Engineering notes

- Use a raw client. Many HTTP libraries normalize header case, recalculate `Content-Length`, remove duplicate headers, or forbid HTTP/2 newline injection.
- For HTTP/1 labs, raw TLS over a CONNECT proxy is enough: connect to the proxy, issue `CONNECT lab:443`, wrap TLS with SNI, then send exact bytes.
- For HTTP/2 labs, use a tool that can send unusual H2 frames and headers. Browser APIs are usually too high-level.
- Response queue poisoning can get the back-end connection into a bad state. Send a few normal requests if the lab documents periodic reset behavior.
- Request-capture labs require length tuning.
- Cache labs require timing discipline. Avoid poisoning the target cache key with your own redirect, login page, or 404.
- Victim-scheduled labs often require repeated delivery. A miss does not always mean the payload is wrong.

## 11. Defense and detection

Hardening:

- Use one consistent HTTP parser policy across the edge, proxy, cache, and origin.
- Reject requests containing both `Content-Length` and `Transfer-Encoding`.
- Reject duplicate or malformed `Transfer-Encoding` headers.
- Strip HTTP/1-only length headers during HTTP/2 downgrade.
- Forbid CRLF in HTTP/2 header names, values, and pseudo-header values before downgrade.
- Close upstream connections after ambiguous or invalid requests.
- Do not place admin trust in `Host: localhost`, client-IP headers, or front-end-added headers alone.
- Mark authenticated pages as `Cache-Control: private, no-store`.
- Regression-test redirecting directories, static resources, and unusual endpoints for CL.0/0.CL behavior.

Detection ideas:

- Requests containing CL+TE, duplicate TE, mixed-case TE, or invalid TE values.
- Bodies beginning with `0\r\n\r\n` followed by an HTTP request line.
- Back-end logs showing `GPOST`, nested request lines, `X-Ignore`, or unexpected `Host` headers.
- HTTP/2 requests carrying HTTP/1-only length headers or CRLF-like bytes in header values.
- Static resources returning account HTML, redirects to untrusted hosts, or unexpected JavaScript origins.
- Comment or profile fields containing raw HTTP headers and cookies.
- Response queue anomalies where one client's request receives another user's account or admin response.

No lab in this series required a hard Collaborator/OAST dependency; same-site lab behavior, exploit-server logs, or direct response observation were sufficient.
