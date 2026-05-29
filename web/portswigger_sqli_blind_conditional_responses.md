# PortSwigger SQL Injection — Blind SQL injection with conditional responses

- Platform: PortSwigger Web Security Academy
- Category: SQL injection
- Difficulty: PRACTITIONER
- Result: solved

## Technique

boolean oracle via Welcome back

## Key details

- Injection/object: `TrackingId`
- Table/columns/channel: `SUBSTRING/LENGTH`
- Key result: `jsnlntzsw32m674bqe2i`

## Payload

```text
TrackingId=x' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='j'--
```

## Notes

This lab belongs to the advanced half of PortSwigger's SQL injection track. The workflow is to identify the available oracle or output channel, extract the administrator credential if required, and log in as administrator to trigger the solved state.

## Defensive takeaway

Parameterized queries are the root fix. Error suppression, WAF filters, and metadata permission reduction are useful defense-in-depth, but they do not replace binding untrusted input as data.
