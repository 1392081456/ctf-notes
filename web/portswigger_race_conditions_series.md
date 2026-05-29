# PortSwigger Race Conditions 1-6 — State Transitions Must Be Atomic

This is a consolidated walkthrough of the six PortSwigger Race Conditions labs.

All labs were completed in the authorized Web Security Academy environment. The main lesson is that race conditions appear when validation, mutation, confirmation, and asynchronous side effects are not treated as one atomic state transition.

## 1. Overview

| # | Lab | Race window | Core idea |
|---|-----|-------------|-----------|
| 1 | Limit overrun race conditions | coupon check before used-state update | parallel `POST /cart/coupon` requests stack discounts |
| 2 | Bypassing rate limits via race conditions | failed-login counter update | single-packet password attempts beat account lockout |
| 3 | Multi-endpoint race conditions | checkout validation before order confirmation | add the jacket while checkout is validating a cheaper cart |
| 4 | Single-endpoint race conditions | pending email overwrite before email rendering | receive a confirmation link for the target email |
| 5 | Exploiting time-sensitive vulnerabilities | timestamp-derived reset token | align two sessions so your token matches Carlos's token |
| 6 | Partial construction race conditions | user row exists before token initialization | race registration against `token[]=` confirmation |

## 2. Testing model

Race testing is a state-machine exercise:

1. Identify the transition: coupon, login counter, checkout, email change, reset token, registration.
2. Split the transition into check, write, confirm, and side effect.
3. Benchmark normal sequential behavior.
4. Send grouped requests in parallel.
5. For HTTP/2 targets, prefer gate-based single-packet release.
6. Reset application state between attempts.

## 3. Limit and rate races

The coupon lab applies a single-use discount. Sequential requests behave correctly: first success, later requests fail. Parallel requests can all observe the pre-update state and apply the discount repeatedly. Once the total drops below store credit, purchase the jacket.

The login lab rate-limits per username. A Turbo Intruder gate queues one request per candidate password and releases them together:

```python
for password in passwords:
    engine.queue(target.req, password, gate='1')
engine.openGate('1')
```

The successful response identifies the password before the account lock is fully applied.

## 4. Multi-endpoint and single-endpoint races

The multi-endpoint lab combines:

```text
POST /cart
POST /cart/checkout
```

The goal is to pass checkout validation while the cart still looks affordable, then have the expensive item included before final confirmation. Connection warm-up helps distinguish network delay from business processing delay.

The single-endpoint email lab is subtler. The application stores one pending email address. Parallel updates can make the email recipient and the email body disagree. Send one change to an inbox you control and one to `carlos@ginandjuice.shop`. If the controlled inbox receives a confirmation email whose body references the target address, the confirmation link claims that address and inherits the pending admin invite.

## 5. Time-sensitive and partial-construction races

The password-reset lab is not a classic shared-state race. It abuses predictable token generation. Same-session requests are serialized by PHP session locking, so use two sessions. When two reset requests line up exactly, the tokens can match. Replace one username with `carlos`, then reuse the token from your email by changing the username parameter in the reset link.

The partial-construction lab targets a registration flow. Static JavaScript reveals:

```http
POST /confirm?token=...
```

An empty token is blocked, but `token[]=` reaches a different parser path:

```http
POST /confirm?token[]= HTTP/2
```

Queue one registration request and many confirmation requests in the same gate. A successful confirmation response names the registered username; log in with that username and the registration password.

## 6. Defense and detection

Hardening:

- wrap check-and-act logic in transactions, row locks, unique constraints, or compare-and-set operations;
- make coupon application, balance checks, login counters, and pending-email updates atomic;
- bind asynchronous emails to immutable snapshots;
- generate reset tokens with CSPRNGs and bind them to user, purpose, and expiry;
- never expose partially constructed objects to confirmation or login flows;
- serialize or deduplicate critical operations per user/resource.

Detection:

- many identical state-changing requests in a narrow time window;
- more coupon successes than allowed by business rules;
- login attempts exceeding lockout counters;
- checkout success after insufficient-funds responses;
- email recipients and confirmation-body addresses diverging;
- reset tokens duplicated across requests;
- unusual confirmation parameters such as `token[]=` or empty-array tokens.

No lab in this series required a Collaborator/OAST channel.
