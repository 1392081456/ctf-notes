# PortSwigger SQL Injection — Blind SQL injection with time delays and information retrieval

- Platform: PortSwigger Web Security Academy
- Category: SQL injection
- Difficulty: PRACTITIONER
- Result: solved

## Technique

time-based extraction

## Key details

- Injection/object: `TrackingId`
- Table/columns/channel: `ASCII binary search + retry`
- Key result: `v7mewzxcvljbd3456c4n`

## Payload

```text
'||(SELECT CASE WHEN (...) THEN pg_sleep(1.5) ELSE pg_sleep(0) END FROM users WHERE username='administrator')--
```

## Notes

This lab belongs to the advanced half of PortSwigger's SQL injection track. The workflow is to identify the available oracle or output channel, extract the administrator credential if required, and log in as administrator to trigger the solved state.

## Defensive takeaway

Parameterized queries are the root fix. Error suppression, WAF filters, and metadata permission reduction are useful defense-in-depth, but they do not replace binding untrusted input as data.
