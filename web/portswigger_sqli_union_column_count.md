# PortSwigger SQL Injection — SQL injection UNION attack, determining the number of columns returned by the query

- Platform: PortSwigger Web Security Academy
- Category: SQL injection
- Difficulty: PRACTITIONER
- Result: solved

## Technique

UNION NULL count

## Key details

- Injection/object: `3 columns`
- Table/columns/channel: `N/A`
- Key result: `N/A`

## Payload

```text
Lifestyle' UNION SELECT NULL,NULL,NULL--
```

## Notes

This lab belongs to the advanced half of PortSwigger's SQL injection track. The workflow is to identify the available oracle or output channel, extract the administrator credential if required, and log in as administrator to trigger the solved state.

## Defensive takeaway

Parameterized queries are the root fix. Error suppression, WAF filters, and metadata permission reduction are useful defense-in-depth, but they do not replace binding untrusted input as data.
