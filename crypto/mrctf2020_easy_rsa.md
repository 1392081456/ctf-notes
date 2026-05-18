# MRCTF 2020 Easy_RSA — Factoring `n` from `φ(n)` and from `e·d`

> **Flag**: `MRCTF{...}` (organiser-rotated)
>
> Two textbook RSA reductions chained together. The challenge gives you two pairs of derived primes (`_P`, `_Q`) and asks you to decrypt a ciphertext encrypted under `e=65537, n=_P*_Q`. To get `_P`, you must factor an intermediate `n_1` knowing only `n_1` and `φ(n_1)`. To get `_Q`, you must factor a different `n_2` knowing only `n_2` and a public-exponent / private-exponent pair `(e_2, d_2)`. Both reductions are classic — recovering `p, q` from `(n, φ(n))` is high-school Vieta's, and recovering them from `(n, e, d)` is a short search over the small unknown `k = (e·d - 1) / φ(n)`. The writeup is mostly about getting the two-stage chain wired correctly without losing track of which `n` is which.

## 0. Problem setup

The challenge generates two "intermediate" primes:

```python
def gen_p():
    p, q = getPrime(512), getPrime(512)
    n1   = p * q
    phi1 = (p - 1) * (q - 1)
    print(f"n1 = {n1}")
    print(f"phi1 = {phi1}")
    _P = nextprime(2021*p + 2020*q)
    return _P

def gen_q():
    p, q = getPrime(512), getPrime(512)
    n2 = p * q
    e2 = 65537
    d2 = inverse(e2, (p-1)*(q-1))
    print(f"n2 = {n2}")
    print(f"e2 = {e2}")
    print(f"d2 = {d2}")
    _Q = nextprime(abs(2021*p - 2020*q))
    return _Q

_P, _Q = gen_p(), gen_q()
N = _P * _Q
e = 65537
c = pow(flag_int, e, N)
print(f"N = {N}, c = {c}")
```

We're given `(n1, phi1)`, `(n2, e2, d2)`, `N`, `c`. Goal: recover the flag.

## 1. Stage 1 — `(n, φ(n)) → (p, q)`

The standard reduction. From the identities:

```
n   = p·q
φ(n) = (p-1)(q-1) = n - (p+q) + 1
```

We can solve for `p + q`:

```
p + q = n - φ(n) + 1
```

And we know `p · q = n`. Two values whose sum and product we know are roots of a quadratic — Vieta's formulas:

```
t² - (p+q)·t + n = 0

      (p+q) ± √((p+q)² - 4n)
p, q = ─────────────────────
                2
```

```python
from gmpy2 import isqrt

s = n1 - phi1 + 1            # p + q
disc = isqrt(s*s - 4*n1)     # √(discriminant)
p1, q1 = (s + disc) // 2, (s - disc) // 2
assert p1 * q1 == n1

# Now reconstruct _P
_P_inner = 2021*p1 + 2020*q1
_P = next_prime(_P_inner)    # or 2021*q1 + 2020*p1, depending on order
```

The `p, q` order isn't determined by Vieta's alone — both `2021p+2020q` and `2021q+2020p` are valid candidates. Try both and continue to stage 2 with each; one will give a `_Q` that produces a valid decryption, the other won't.

## 2. Stage 2 — `(n, e, d) → (p, q)`

The key fact: `e·d ≡ 1 (mod φ(n))`. That means there exists some integer `k` such that:

```
e·d - 1 = k · φ(n)
```

`k` is small. Specifically `d < φ(n)`, so `e·d - 1 < e·φ(n)`, giving `k < e = 65537`. That's a **17-bit search space at most**.

For each candidate `k` from 1 to e-1:

1. Compute `candidate_phi = (e·d - 1) / k`. Must be integer division — skip if `(e·d - 1) % k != 0`.
2. Check whether `candidate_phi` plausibly equals `φ(n)`. Use Vieta's: derive `p + q` from `candidate_phi`, check if the quadratic has integer roots, check if those roots multiply to `n`.

```python
def factor_from_ed(n, e, d):
    target = e*d - 1
    for k in range(1, e):
        if target % k != 0:
            continue
        phi = target // k
        s   = n - phi + 1
        disc_sq = s*s - 4*n
        if disc_sq < 0:
            continue
        disc = isqrt(disc_sq)
        if disc*disc != disc_sq:
            continue
        p = (s + disc) // 2
        q = (s - disc) // 2
        if p * q == n:
            return p, q
    raise ValueError("could not factor")
```

In practice `k` is found within hundreds of iterations — `gcd(e·d - 1, n)` heuristics can narrow it further, but brute search over 65537 candidates is microseconds in Python.

## 3. Reconstructing `_Q` and decrypting

Once we have `p2, q2`, both order options for `2021p - 2020q` and `2020p - 2021q`:

```python
_Q_candidates = [
    abs(2021*p2 - 2020*q2),
    abs(2021*q2 - 2020*p2),
    abs(2020*p2 - 2021*q2),
    abs(2020*q2 - 2021*p2),
]
# next_prime each, then check which produces N when multiplied by _P
for q_inner in _Q_candidates:
    _Q = next_prime(q_inner)
    if _P * _Q == N:
        d_final = inverse(e, (_P-1)*(_Q-1))
        m = pow(c, d_final, N)
        print(long_to_bytes(m))
        break
```

## 4. Full exploit

```python
#!/usr/bin/env python3
from gmpy2 import isqrt, next_prime, invert
from Crypto.Util.number import long_to_bytes

# --- inputs from challenge output ---
n1   = ...
phi1 = ...
n2   = ...
e2   = 65537
d2   = ...
N    = ...
c    = ...

# --- stage 1: (n1, phi1) → (p1, q1) → _P ---
s = n1 - phi1 + 1
disc = isqrt(s*s - 4*n1)
p1, q1 = (s + disc) // 2, (s - disc) // 2
assert p1 * q1 == n1

P_candidates = [next_prime(2021*p1 + 2020*q1),
                next_prime(2021*q1 + 2020*p1)]

# --- stage 2: (n2, e2, d2) → (p2, q2) → _Q ---
target = e2*d2 - 1
for k in range(1, e2):
    if target % k != 0:
        continue
    phi_n2 = target // k
    s2     = n2 - phi_n2 + 1
    disc_sq = s2*s2 - 4*n2
    if disc_sq < 0:
        continue
    disc2 = isqrt(disc_sq)
    if disc2*disc2 != disc_sq:
        continue
    p2 = (s2 + disc2) // 2
    q2 = (s2 - disc2) // 2
    if p2 * q2 == n2:
        break

Q_candidates = [next_prime(abs(2021*p2 - 2020*q2)),
                next_prime(abs(2021*q2 - 2020*p2))]

# --- combine and decrypt ---
for _P in P_candidates:
    for _Q in Q_candidates:
        if _P * _Q == N:
            d_final = invert(65537, (_P-1)*(_Q-1))
            m = pow(c, d_final, N)
            print(long_to_bytes(int(m)))
```

## 5. Traps and lessons learned

| Trap | Why it cost me time | Resolution |
|---|---|---|
| Used `math.isqrt` on Python 3.7 | `math.isqrt` arrived in 3.8; older interpreters threw `AttributeError` | Use `gmpy2.isqrt` or roll your own Newton's method for arbitrary precision sqrt |
| Forgot to check `disc*disc == disc_sq` | Skipped the "is the discriminant a perfect square" verification, got non-integer p, q | Always verify perfect-squareness after `isqrt`; floor truncates and gives wrong p, q otherwise |
| Tried only one ordering of `_P` / `_Q` | Submitted decryption that returned garbage; assumed a different bug | Vieta's doesn't determine which root is `p` vs `q`. Always try both orderings — usually only one matches `_P * _Q == N` |
| Missed `nextprime` step | Tried `_P = 2021*p1 + 2020*q1` directly | The challenge wraps with `next_prime(...)`. Reconstruct the inner value, then call `next_prime` to match what the challenge computed |
| Brute-force k looped to infinity | Wrote `range(1, target)` (huge) by mistake | `k < e`, not `k < target`. Always reread the bound — it's the public exponent, not the ciphertext |

## 6. Methodology takeaways

1. **Recognise the two standard RSA-from-leak shapes immediately.**
   - `(n, φ(n))` → Vieta's quadratic
   - `(n, e, d)` → small-k brute force (k < e ≈ 17 bits)
   - `(n, p+q)`, `(n, p-q)`, `(n, p XOR q)` → variations with similar shapes
   - Knowing the family of reductions saves you from reinventing each one
2. **Vieta's formula is a recurring CTF crypto motif.** Whenever you can express `p + q` and `p · q`, you can recover `p` and `q`. Look for any leak that hands you (sum, product) or (difference, product).
3. **`k = (e·d - 1) / φ(n)` is bounded by `e`.** This is the key bound that makes the `(e, d) → factorisation` reduction practical. Without that bound, you'd be searching a 1024+-bit space.
4. **Order ambiguity must be handled by trying all combinations.** When the challenge derives `_P = f(p, q)` for some asymmetric `f`, you don't know which Vieta's root is which original prime. Try every permutation.
5. **In multi-stage RSA challenges, the consistency check is `_P * _Q == N`.** Always reconstruct and verify before attempting decryption.

## 7. Related techniques

- [Factoring with $\phi$ and $n$](https://crypto.stanford.edu/~dabo/papers/RSA-survey.pdf) — Boneh's RSA survey, section on "Factoring N given d"
- [`RsaCtfTool`](https://github.com/RsaCtfTool/RsaCtfTool) — automates these reductions and many others
- [`crypto-attacks` repo](https://github.com/jvdsn/crypto-attacks) by jvdsn — minimal reference implementations
