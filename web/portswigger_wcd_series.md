# PortSwigger Web Cache Deception 1-5 — Cache/Origin Path Discrepancies

A consolidated walkthrough of all five PortSwigger Web Cache Deception (WCD) labs, treated as one methodology track. Individual lab notes are under `labs/`.

**Thesis:** WCD is a *path-interpretation discrepancy* between the cache and the origin. The cache thinks a URL is a cacheable static asset; the origin resolves it to a dynamic, private page. The cache key omits the session cookie, so the victim's authenticated response is stored under an attacker-knowable URL.

## 1. Overview table

| # | Lab | Difficulty | Discrepancy | Crafted URL | Why it works |
|---|-----|-----------|-------------|-------------|--------------|
| 1 | path mapping | Apprentice | path mapping | `/my-account/wcd.js` | origin maps `/my-account/<x>`→`/my-account`; cache caches by `.js` |
| 2 | path delimiters | Practitioner | path delimiter | `/my-account;wcd.js` | origin treats `;` as delimiter→`/my-account`; cache caches whole string as `.js` |
| 3 | origin normalization | Practitioner | **origin** normalizes | `/resources/..%2fmy-account?wcd` | cache matches `/resources/*` rule; **origin** decodes `%2f`+resolves `..`→`/my-account` |
| 4 | cache server normalization | Practitioner | **cache** normalizes (mirror of #3) | `/my-account%23%2f%2e%2e%2fresources?wcd` | origin does NOT normalize, `%23` is a delimiter→`/my-account`; **cache** resolves the dot-segment→matches `/resources` rule |
| 5 | exact-match cache rules | **Expert** | exact filename rule + cache normalization + `;` | `/my-account;%2f%2e%2e%2frobots.txt?wcd` | cache normalizes→resolves to `/robots.txt` (exact-match rule); origin reads up to `;`→`/my-account` |

Labs 1-4 read carlos's API key. **Lab 5 differs**: leak the administrator's CSRF token, then change their email via CSRF.

### Three axes that classify every lab
- **What the cache caches**: extension (`.js`, #1/#2), static-dir prefix (`/resources`, #3/#4), exact filename (`/robots.txt`, #5).
- **Who normalizes**: origin (#3) vs cache (#4/#5) — opposite directions, so the payload structure flips (origin-normalizes puts the dot-segment after `/resources`; cache-normalizes puts it after `/my-account`).
- **Which delimiter truncates the origin to `/my-account`**: `;` (#2/#5), `%23` (#4 — never a raw `#`, the browser treats it as a fragment). Fuzz `/my-account§§abc` against a delimiter list to find one returning 200 + sensitive data.

## 2. Unified exploitation chain

1. Log in as `wiener:peter`; confirm `/my-account` contains the secret (API key / CSRF token).
2. Find the discrepancy: request the crafted URL with your cookie; confirm it returns the account page (200) and is cached (`X-Cache: hit`, TTL ~30s).
3. Deliver `<script>document.location="https://LAB/<crafted>"</script>` to the victim; their authenticated page caches under that URL.
4. Fetch the same URL with no cookie → read the victim's secret.
5. Labs 1-4: submit carlos's key. **Lab 5: a second CSRF round** — auto-submit `POST /my-account/change-email` with the leaked admin CSRF token to change the admin's email.

## 3. Operational gotchas (the real value; not in the official solution)

- **The `302 → /login` is cached too.** Requesting the crafted URL before the victim caches the login redirect and self-poisons. Use a fresh cache-buster each attempt.
- **The grab race (hit in lab 4).** After the victim loads `/exploit`, their browser's request to the crafted URL arrives ~1-2s later. Grabbing the instant you detect the victim caches the `302` ahead of them. **Wait ~4s after detecting the victim, then grab.**
- **TTL ~30s and you can't poll the crafted URL (it poisons).** Poll the exploit server access log for the `(Victim)` UA, then (after the delay) fetch the crafted URL.
- **Programmatic `DELIVER_TO_VICTIM` (curl) gets rate-limited; a browser click is reliable.** Deliver sparingly.
- **`DELIVER` without `STORE` doesn't persist `/exploit`** (a later browser click delivers an empty form). STORE first.
- **`curl --path-as-is` is mandatory for labs 3/4/5**, else curl collapses `../` client-side.
- **Never a raw `#` delimiter** — the browser treats it as a fragment; use `%23` (lab 4).
- **Lab instances expire** (DNS fails / HTTP times out); re-access for a fresh URL.

## 4. Defense and detection

- **Key the cache on the full, normalized path, and use identical path parsing/normalization on cache and origin** (same handling of `;`/`%23` delimiters, `.js` trailing-segment mapping, `%2f`/`..` decoding). The discrepancy is the root cause.
- **Never cache dynamic/authenticated responses** (`Cache-Control: no-store` on account pages and any `Set-Cookie` response; the cache must skip them).
- **Don't decide cacheability by URL shape** (extension / static-dir prefix / exact filename) — honor the origin's real `Content-Type`/`Cache-Control`.
- Serve static assets from an isolated path/host.
- **Detection:** `text/html` hitting a static cache rule; the same "static" URL returning different per-user content (keys/usernames/CSRF tokens); paths with `;`, `%23`, `%2f`, `%2e%2e`, `..`; a sensitive write (`POST /my-account/change-email`) following a WCD-style cached fetch (CSRF chain).
