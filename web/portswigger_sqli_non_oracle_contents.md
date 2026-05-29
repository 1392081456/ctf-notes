# PortSwigger SQL Injection — SQL injection attack, listing the database contents on non-Oracle databases

- Platform: PortSwigger Web Security Academy
- Category: SQL injection
- Difficulty: PRACTITIONER
- Result: solved

## Technique

information_schema.tables / information_schema.columns

## Key details

- Injection/object: `users_uxtdkb`
- Table/columns/channel: `username_qzummn / password_gdfjfq`
- Key result: `a1r4bp0qg7405fvogmrf`

## Payload

```text
Gifts' UNION SELECT table_name,NULL FROM information_schema.tables--
```

## Notes

This lab belongs to the advanced half of PortSwigger's SQL injection track. The workflow is to identify the available oracle or output channel, extract the administrator credential if required, and log in as administrator to trigger the solved state.

## Defensive takeaway

Parameterized queries are the root fix. Error suppression, WAF filters, and metadata permission reduction are useful defense-in-depth, but they do not replace binding untrusted input as data.
