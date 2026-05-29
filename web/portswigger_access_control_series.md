# PortSwigger Access Control 1-13 — Authorization Belongs on the Server

This is a consolidated walkthrough of the 13 PortSwigger access control labs.

All labs were solved in the authorized Web Security Academy environment. The durable lesson is simple: authorization must be enforced server-side on the resource and action being performed. Hidden URLs, client-side roles, GUIDs, redirects, methods, and Referer headers are not authorization.

## 1. Overview

| # | Lab | Class | Core flaw |
|---|-----|-------|-----------|
| 1 | unprotected admin functionality | vertical access control | `robots.txt` discloses admin path |
| 2 | unprotected admin with unpredictable URL | vertical access control | JavaScript discloses hidden admin path |
| 3 | role controlled by request parameter | client-side trust | forge `Admin=true` cookie |
| 4 | role modified in profile | mass assignment | add `"roleid":2` to JSON |
| 5 | user ID controlled by request parameter | IDOR | change `id=wiener` to `id=carlos` |
| 6 | unpredictable user IDs | IDOR | carlos GUID leaks from author link |
| 7 | data leakage in redirect | IDOR + redirect body | 302 body still contains API key |
| 8 | password disclosure | IDOR + overexposure | `id=administrator` reveals prefilled password |
| 9 | insecure direct object references | predictable object reference | transcript `1.txt` leaks password |
| 10 | URL-based access control bypass | front-end/back-end routing mismatch | `X-Original-URL` |
| 11 | method-based bypass | method inconsistency | GET performs upgrade without same check |
| 12 | multi-step process flaw | state machine auth gap | confirmation step lacks access control |
| 13 | Referer-based access control | header trust | non-admin session with admin Referer |

## 2. Testing model

```text
Vertical checks:
  Can a normal user reach admin functionality?
  Is the admin URL hidden in robots.txt, JS, comments, or source?
  Is role state client-controlled?
  Do gateway and back end agree on the route?

Horizontal checks:
  Can id/user/guid/file/transcript be changed?
  Is an unpredictable ID disclosed elsewhere?
  Does a redirect body leak data?
  Does the response expose passwords/API keys unnecessarily?

Workflow checks:
  Does every step enforce authorization?
  Do all HTTP methods enforce the same policy?
  Is Referer/Origin being mistaken for authorization?
```

## 3. Vertical access control failures

The first two labs are not bypasses so much as missing authorization:

- `robots.txt` discloses `/administrator-panel`.
- JavaScript discloses an unpredictable admin URL.

Hidden routes are discovery controls at best. They do not decide who is allowed to delete a user.

Client-side role trust appears in two forms. One lab accepts:

```http
Admin=true
```

as a cookie. Another accepts a role field added to a profile update:

```json
{"roleid": 2}
```

Both are the same bug: the client is allowed to define its own privilege.

## 4. IDOR and object references

The basic account IDOR changes:

```http
/my-account?id=wiener
```

to:

```http
/my-account?id=carlos
```

The GUID variant only makes enumeration harder. Carlos's GUID appears in a blog author link, so the account endpoint can still be called with that identifier.

The redirect-body lab is a useful operational reminder: automatic redirect following can hide the vulnerable response. The 302 response is unauthorized, but its body still contains Carlos's API key.

The password-disclosure lab shows overexposure. The account page includes the current password as a masked input value. Changing `id=administrator` exposes the administrator password, which can then be used to log in and delete `carlos`.

The IDOR transcript lab uses predictable filenames. Chat logs are static text files with incrementing names; `1.txt` contains Carlos's password.

## 5. Routing, methods, and workflows

URL-based access control fails when the front end and back end use different route sources:

```http
GET /?username=carlos HTTP/1.1
X-Original-URL: /admin/delete
```

The front end sees `/`; the back end honors `/admin/delete`.

Method-based access control fails when POST is protected but GET reaches the same action:

```http
GET /admin-roles?username=wiener&action=upgrade
```

Multi-step workflows fail when only the first step is protected. Replaying the confirmation request with a non-admin session promotes the attacker.

Referer-based access control fails because Referer is a request header, not an authority source. A non-admin session with a Referer that appears to come from `/admin` can replay the role-change request.

## 6. Defense and detection

Hardening:

- Enforce authorization on every sensitive server-side endpoint.
- Base authorization on server-side session state and permission models.
- Never trust role, admin, owner, or user ID values supplied by the client.
- Check owner/resource/action for every object access.
- Treat GUIDs as identifiers, not permissions.
- Do not include sensitive data in redirect bodies.
- Validate every step of a multi-step workflow.
- Apply the same authorization policy across HTTP methods.
- Do not use Referer as authorization.
- Disable or constrain route override headers such as `X-Original-URL` and `X-Rewrite-URL`.

Detection ideas:

- Normal users requesting `/admin`, `/administrator-panel`, `/admin-roles`, or `/admin/delete`.
- Client-supplied `Admin=true`, `roleid=2`, or unexpected role fields in JSON.
- One session iterating `id`, GUID, filename, or transcript identifiers.
- 302 responses containing account data, passwords, or API keys.
- State-changing GET requests.
- Non-admin sessions carrying admin Referer values.
- Requests with URL override headers.

No lab in this series required Collaborator/OAST. The invariant is that every final action must enforce authorization at the server-side handler that performs it.
