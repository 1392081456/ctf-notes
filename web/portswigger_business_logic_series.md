# PortSwigger Business Logic Vulnerabilities 1-12 — Invariants Must Be Server-Side

This is a consolidated walkthrough of the twelve PortSwigger Business Logic labs.

All labs were solved in the authorized Web Security Academy environment. The main lesson is that business rules are security rules. If the server does not enforce them at every relevant step, normal features become exploit primitives.

## 1. Overview

| # | Lab | Broken invariant | Core idea |
|---|-----|------------------|-----------|
| 1 | excessive trust in client-side controls | server trusts client price | lower `price` in `POST /cart` |
| 2 | high-level logic vulnerability | quantity may be negative | use negative cheap items to offset jacket cost |
| 3 | inconsistent security controls | registration and email-change rules differ | verify normal email, then change to employee domain |
| 4 | flawed business rule enforcement | only consecutive coupon reuse is blocked | alternate `NEWCUST5` and `SIGNUP30` |
| 5 | low-level logic flaw | cart total overflows | add enough units to wrap total |
| 6 | exceptional input | long email handled inconsistently | exploit truncation/validation mismatch |
| 7 | weak isolation on dual-use endpoint | self-service and admin password flows share endpoint | omit `current-password`, set `username=administrator` |
| 8 | insufficient workflow validation | confirmation does not re-check payment | replay order confirmation after adding jacket |
| 9 | flawed state machine | interrupted login defaults to privileged state | drop role-selector request |
| 10 | infinite money | discounted gift card redeems at full value | repeat buy-discount-redeem loop |
| 11 | encryption oracle | one feature encrypts, another decrypts | forge `stay-logged-in` as administrator |
| 12 | email parsing discrepancy | validators and mailer parse differently | UTF-7 encoded-word splits validation and delivery |

## 2. Triage model

Business-logic testing is about invariants:

- Who calculates the price?
- Can quantities be negative, zero, huge, or overflowing?
- Is the same rule enforced on every endpoint?
- Can workflow steps be replayed or skipped?
- What happens if a required parameter is missing?
- Does a state machine fail open when interrupted?
- Do two features accidentally form an oracle?
- Do parsers agree on the canonical value?

The payloads are often boring. The bug is in the rule boundary.

## 3. Cart and money bugs

The first lab accepts a client-supplied price:

```http
productId=1&quantity=1&price=1
```

The fix is not a hidden field. The fix is calculating price server-side from product ID and catalog state.

The negative-quantity lab uses a cheap item as a counterweight. A negative quantity lowers the order total, then the expensive jacket can be added without exceeding store credit.

The low-level logic lab is a numeric boundary failure. The cart total eventually wraps when enough items are added. This is why money logic needs explicit min/max, type, and overflow checks.

The infinite-money lab is a closed loop:

```text
buy $10 gift card with 30% discount -> pay $7 -> redeem $10 -> profit $3
```

Automation only makes the bug faster; the bug is that discounted stored value redeems at face value without anti-arbitrage controls.

## 4. Inconsistent rule enforcement

The employee-domain lab validates registration one way and later email changes another way. A normal address is used for verification, then the account email is changed to the employee domain to unlock admin functionality.

The coupon lab only blocks the same coupon twice in a row. Alternating codes bypasses that memory:

```text
NEWCUST5
SIGNUP30
NEWCUST5
SIGNUP30
```

The exceptional-input lab shows the same pattern with length handling. Validation, delivery, storage, and authorization must agree on the same canonical email value.

## 5. Endpoint isolation and workflow checks

The dual-use password endpoint changes behavior based on parameters. Removing `current-password` makes the endpoint accept a password change, and the `username` parameter selects the victim:

```http
username=administrator
```

Self-service and administrative actions should not share an endpoint unless authorization is explicit and invariant.

The workflow lab replays:

```http
GET /cart/order-confirmation?order-confirmation=true
```

after adding the expensive product. The confirmation step should validate payment state, basket contents, and user balance again.

The state-machine lab drops the role-selection request after login. The session falls into the administrator role. Interrupted workflows must fail closed.

## 6. Oracles and parser discrepancies

The encryption-oracle lab combines two features:

- invalid comment email creates an encrypted `notification` cookie;
- a later page decrypts that cookie and reflects the plaintext.

This reveals the `stay-logged-in` format:

```text
username:timestamp
```

Encrypt `administrator:<timestamp>`, remove the error-prefix block with correct padding, then use the ciphertext as the remember-me cookie.

The expert email lab uses parser disagreement. The server validator accepts a value that appears to end in `@ginandjuice.shop`, while the mailer decodes UTF-7 encoded-word content and sends confirmation to the attacker's Academy inbox:

```text
=?utf-7?q?attacker&AEA-EMAIL-ID&ACA-?=@ginandjuice.shop
```

The defense is one parser and one canonical form for validation, storage, authorization, and delivery.

## 7. Defense and detection

Hardening:

- Calculate price, discounts, balance, inventory, role, and user identity server-side.
- Reject negative, zero, huge, overflowing, and malformed numeric inputs.
- Centralize shared business rules.
- Validate every workflow step independently.
- Split self-service and administrative endpoints, or enforce explicit authorization on both paths.
- Fail closed on interrupted state machines.
- Context-bind encrypted cookies and avoid reusable encrypt/decrypt oracles.
- Use one canonical parser for complex inputs such as email addresses.

Detection:

- Client changes to `price`, `quantity`, `discount`, `role`, `username`, or `email`.
- Negative or huge quantities and repeated coupon alternation.
- Missing `current-password` on password-change requests.
- Direct order-confirmation replay.
- Login sessions that skip role selection.
- Rapid gift-card buy/redeem loops.
- Encoded-word, UTF-7, multiple-`@`, or unusually long email registrations.

No lab in this series required a Collaborator/OAST channel.
