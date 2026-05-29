# PortSwigger SQL Injection — Blind SQL injection with conditional errors

- Platform: PortSwigger Web Security Academy
- Category: SQL injection
- Difficulty: PRACTITIONER
- Result: solved

## Technique

conditional error oracle

## Key details

- Injection/object: `TrackingId`
- Table/columns/channel: `CASE WHEN TO_CHAR(1/0)`
- Key result: `uwyumy70li0mmuuskenx`

## Payload

```text
'||(SELECT CASE WHEN (...) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```

## Notes

This lab belongs to the advanced half of PortSwigger's SQL injection track. The workflow is to identify the available oracle or output channel, extract the administrator credential if required, and log in as administrator to trigger the solved state.

## Defensive takeaway

Parameterized queries are the root fix. Error suppression, WAF filters, and metadata permission reduction are useful defense-in-depth, but they do not replace binding untrusted input as data.
