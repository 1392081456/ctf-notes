# PortSwigger Authentication 1-14 — State Machines, Oracles, and Tokens

This is a consolidated walkthrough of the 14 PortSwigger authentication labs.

All labs were solved in the authorized Web Security Academy environment. The main lesson is that authentication breaks when one step of the state machine leaks an oracle, trusts client-controlled identity, or stores a secret in a predictable format.

## 1. Overview

| # | Lab | Class | Core flaw |
|---|-----|-------|-----------|
| 1 | username enumeration via different responses | username oracle | `Invalid username` vs `Incorrect password` |
| 2 | 2FA simple bypass | MFA state gap | password login lets user browse directly to `/my-account` |
| 3 | password reset broken logic | reset token binding | token not checked on final reset; hidden username trusted |
| 4 | subtly different responses | username oracle | punctuation/trailing-space difference |
| 5 | response timing | timing oracle | valid usernames take longer with long passwords |
| 6 | broken brute-force protection, IP block | rate-limit logic | successful login resets failure counter |
| 7 | account lock enumeration | lock oracle | real users trigger lock message |
| 8 | 2FA broken logic | MFA user binding | `verify` parameter can target `carlos` |
| 9 | stay-logged-in brute force | predictable remember-me | `base64(username:md5(password))` |
| 10 | offline password cracking | XSS + weak cookie | steal cookie, crack MD5 offline |
| 11 | password reset poisoning | host header trust | `X-Forwarded-Host` controls reset link host |
| 12 | password change brute force | error oracle | mismatched new passwords reveal correct current password |
| 13 | multiple credentials per request | bulk credential logic | JSON password array treated as one request |
| 14 | 2FA brute force | MFA brute force | repeat login macro and brute-force code |

## 2. Testing model

```text
Login:
  Do invalid username and invalid password produce different text, status, length, or timing?
  Does rate limiting bind to IP, username, session, or request count?

2FA:
  Is the MFA challenge bound to the authenticated user and current session?
  Can the protected page be reached before MFA completion?
  Can MFA codes be retried or brute-forced?

Reset/change password:
  Is the reset token checked on the final action?
  Is the token bound to the target user?
  Can Host/X-Forwarded-Host poison generated links?
  Do change-password errors reveal the current password?

Persistent login:
  Is the remember-me cookie random and server-side verified?
  Or is it a reversible/hashable username-password construction?
```

## 3. Username oracles

The obvious version uses different messages:

```text
Invalid username
Incorrect password
```

The subtle version differs by punctuation or whitespace. This is why enumeration checks should compare normalized body length, extracted error text, and byte-level diffs, not just visual appearance.

The timing version uses a longer password to amplify the cost difference for valid usernames. Varying `X-Forwarded-For` bypasses a naive IP-based limiter.

Account lock is another oracle. Repeating attempts for each username reveals which account reaches the lock threshold.

## 4. Brute-force protection mistakes

One lab resets the failure counter after a successful login. Interleave attempts:

```text
carlos:candidate
wiener:peter
carlos:next-candidate
wiener:peter
```

Another lab accepts multiple passwords in one JSON request:

```json
{
  "username": "carlos",
  "password": ["123456", "password", "qwerty"]
}
```

The server tries the array values but counts the whole request once.

## 5. MFA state bugs

The simple bypass is a state machine failure. After password authentication, browsing directly to `/my-account` works even though MFA was not completed.

The broken-logic MFA lab lets the client choose which user the challenge applies to:

```text
verify=carlos
```

The brute-force MFA lab requires a macro-like loop:

```text
GET /login
POST /login
GET /login2
POST /login2 mfa-code=0000..9999
```

The invariant is that MFA challenge, code, session, and user must be bound together server-side.

## 6. Password reset and password change

The broken reset lab trusts the hidden `username` on the final reset request and does not enforce the token:

```text
username=carlos
```

The reset poisoning lab trusts `X-Forwarded-Host` when building password reset links:

```http
X-Forwarded-Host: EXPLOIT-SERVER
```

The victim clicks a link to the attacker's host, leaking the reset token in the access log.

The password-change lab exposes an oracle:

```text
wrong current + mismatched new passwords -> current password incorrect
correct current + mismatched new passwords -> new passwords do not match
```

That difference identifies the current password.

## 7. Remember-me and offline cracking

The vulnerable persistent-login token is:

```text
base64(username + ":" + md5(password))
```

For brute force, generate candidate cookies for `carlos` and look for the authenticated account page.

For offline cracking, stored XSS steals Carlos's cookie, the Base64 wrapper reveals the MD5 hash, and the hash is cracked locally with a dictionary. The security failure is not Base64; it is storing a deterministic password-derived value client-side.

## 8. Defense and detection

Hardening:

- Make login failures uniform in text, status, length, and timing.
- Rate-limit by username, IP, device/session, and global risk signals.
- Use fixed-cost password verification paths where practical.
- Bind MFA challenges to user, session, purpose, and expiry.
- Require MFA-complete state before protected resources.
- Bind reset tokens to user and action; make them high-entropy, single-use, and short-lived.
- Build reset links from fixed server configuration, not Host or `X-Forwarded-Host`.
- Use random server-side remember-me tokens, not password-derived cookies.
- Unify password-change error messages.

Detection ideas:

- Large login failure sets with dictionary-shaped usernames or passwords.
- Rotating `X-Forwarded-For` on login attempts.
- Many MFA code submissions per account/session.
- Password reset requests with abnormal Host or `X-Forwarded-Host`.
- Remember-me cookies that decode to `username:hash`.
- Successful known-user logins interleaved with victim brute-force attempts.
- JSON fields changing type, especially password string to password array.

No lab in this series required Collaborator/OAST. Some labs use exploit-server access logs for reset poisoning or cookie theft, but the interaction is same-site Academy infrastructure.
