# PortSwigger JWT 1-8 — Verification Policy Beats Token Shape

This is a consolidated walkthrough of the eight PortSwigger JWT labs.

All labs were solved in the authorized Web Security Academy environment. The main lesson is that JWT security comes from a fixed server-side verification policy, not from the token format itself.

## 1. Overview

| # | Lab | Flaw | Core idea |
|---|-----|------|-----------|
| 1 | unverified signature | server decodes but does not verify | change `sub` to `administrator` |
| 2 | flawed signature verification | accepts unsigned JWTs | `alg:none`, empty signature, trailing dot |
| 3 | weak signing key | weak HMAC secret | hashcat `-m 16500`, re-sign with `secret1` |
| 4 | `jwk` header injection | trusts embedded public key | sign with attacker RSA key and embed JWK |
| 5 | `jku` header injection | fetches untrusted JWKS URL | host attacker JWKS and set `jku` |
| 6 | `kid` path traversal | key ID becomes filesystem path | point `kid` to `/dev/null` |
| 7 | algorithm confusion | RSA public key reused as HMAC secret | change RS256 to HS256 |
| 8 | algorithm confusion, no exposed key | public key derived from signatures | recover RSA public key from valid tokens, then confuse algorithms |

## 2. Triage model

For every JWT:

1. Decode header and payload.
2. Check `alg`, `kid`, `jwk`, and `jku`.
3. Modify a low-risk claim and see whether the signature is verified.
4. Test `alg:none`.
5. If HMAC is used, test weak secret cracking.
6. If key-selection headers are supported, test embedded keys, remote JWKS, and path traversal.
7. If RSA/ECDSA is used, test algorithm confusion.

## 3. Signature verification failures

The first lab accepts a modified payload without a valid signature:

```json
{"sub":"administrator"}
```

The second accepts unsigned tokens:

```json
{"alg":"none","typ":"JWT"}
```

The compact token must retain the trailing dot:

```text
header.payload.
```

The third lab uses a weak HMAC secret. Hashcat mode `16500` cracks JWT HMAC signatures:

```bash
hashcat -a 0 -m 16500 <jwt> jwt.secrets.list
```

The lab secret is `secret1`, which is then used to sign an administrator token.

## 4. Key header attacks

With `jwk` header injection, the server verifies the token using a public key embedded in the token itself. Generate an RSA key pair, sign the modified token, and embed the matching public key in the JWT header.

With `jku`, the token points the server to a JWKS URL:

```json
{
  "jku": "https://EXPLOIT-SERVER/jwks.json",
  "kid": "attacker-key"
}
```

The attacker controls both the signing key and the key-discovery endpoint.

With `kid`, the header is used to build a filesystem path. Traversal to `/dev/null` gives a predictable empty key:

```json
{"kid":"../../../../../../../dev/null"}
```

The token is signed with an empty or null-byte-equivalent HS256 key.

## 5. Algorithm confusion

Algorithm confusion happens when the verifier trusts the token's `alg` and uses the same key material for asymmetric and symmetric verification.

The exposed-key lab provides the RSA public key. Convert it to the same X.509 PEM representation used by the server, set:

```json
{"alg":"HS256"}
```

and use the public key bytes as the HMAC secret.

The no-exposed-key lab starts with two valid RS256 JWTs. Tools such as PortSwigger's `jwt_forgery.py` derive candidate RSA public keys from the signed messages. Once the public key is recovered, the same HS256 confusion path applies.

This does not recover the private key. It abuses a verifier that treats a public key as a symmetric secret.

## 6. Defense and detection

Hardening:

- Pin allowed algorithms server-side.
- Never accept `none`.
- Use verify APIs, not decode-only APIs, for authentication.
- Use strong HMAC secrets or managed key storage.
- Treat `jwk`, `jku`, and `kid` as references to a trusted key registry, not as attacker-provided key material.
- Allowlist `jku` origins.
- Validate `kid` as an opaque ID; forbid path separators and SQL metacharacters.
- Never mix HS and RS verification paths with the same key object.
- Re-check critical authorization state server-side when risk is high.

Detection:

- JWTs with `alg:none`.
- Unexpected `jwk` or external `jku` headers.
- `kid` values containing traversal, `/dev/null`, quotes, or SQL fragments.
- Tokens switching from RS256 to HS256.
- Sudden `sub` or role changes without a corresponding login.
- Outbound requests for unfamiliar JWKS URLs.

No lab in this series required a Collaborator/OAST channel.
