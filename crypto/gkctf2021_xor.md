# GKCTF 2021 XOR — Recovering Prime Factors from XOR + Product

> **Flag**: `flag{md5(a+b+c+d)}`
>
> A clean cryptanalysis challenge with two parts. Part 1 is the well-known "given `n = a*b` and `x = a XOR b`, recover `a` and `b`" problem — solvable bit-by-bit modulo `2^k` (a flavour of Hensel lifting). Part 2 adds a twist: one of the primes is *bit-reversed* in the XOR equation, which couples low bits to high bits and forces a two-ended search. The naive recursion explodes; product-range pruning every few bits keeps it tractable. What I want to record is exactly why the standard solver works on Part 1 and exactly which extra ingredient Part 2 needs.

## 0. Problem setup

Four 512-bit primes `a, b, c, d`. The challenge gives:

```
n1 = a * b
x1 = a XOR b

n2 = c * d
x2 = c XOR reverse_bits(d, 512)      # reverse_bits flips the 512 bits MSB↔LSB

flag = md5(str(a + b + c + d))
```

Goal: recover `a, b, c, d` from `(n1, x1, n2, x2)`.

## 1. The bit-by-bit principle (Part 1)

If we know `a mod 2^k` and want `a mod 2^(k+1)`:

```
a XOR b == x1  →  bit k of b is determined by bit k of a (one XOR away)
a * b == n1    →  congruence (mod 2^(k+1)) constrains bit k of a
```

For each candidate value of `a`'s bit `k` (just 0 or 1):

- Compute the implied bit `k` of `b` via `x1`.
- Substitute into `a * b` and check `(a * b) mod 2^(k+1) == n1 mod 2^(k+1)`.
- Keep only candidates that satisfy the congruence.

Starting with `a mod 2 = 0` or `1` (both candidates), the branching is at most 2 per step. The product congruence kills roughly half of those, so the candidate set stays small (empirically ~few hundred at the top) and converges to a unique solution after 512 bits.

### Part 1 pseudocode

```python
def solve_part1(n, x, nbits):
    # candidates: list of partial a values, each known modulo 2^k
    cands = [0]
    for k in range(nbits):
        new = []
        for a in cands:
            for bit in (0, 1):
                a2 = a | (bit << k)
                b2 = a2 ^ x
                if (a2 * b2) % (1 << (k+1)) == n % (1 << (k+1)):
                    new.append(a2)
        cands = new
    # filter: actual product must match exactly
    return [a for a in cands if a * (a ^ x) == n]
```

This works because `a XOR b == x` pins `b`'s bit `k` once `a`'s is chosen, and the product congruence gives independent verification at each lift.

## 2. Why Part 2 is harder

In Part 2, `x2 = c XOR reverse_bits(d)`. Bit `k` of `c` is coupled to bit `(511-k)` of `d`. That means:

- Choosing `c`'s bit `k` determines `d`'s bit `(511-k)` (via `x2`).
- The product `c * d` congruence at level `2^(k+1)` only involves *low* bits — but we just constrained a *high* bit of `d`.

A bit-by-bit lift on `c` alone doesn't gain information about `d`'s low bits. You'd have to enumerate them separately, blowing up the search.

The fix is to **work both ends at once**:

- At step `k`, you simultaneously pin `c`'s bit `k` (LSB direction) **and** `c`'s bit `(511-k)` (MSB direction). The reverse couples them — `d`'s low bit `k` and high bit `(511-k)` both get determined.
- 4 candidates per step (2 × 2 for the two new bits).
- Product congruence mod `2^(k+1)` still constrains low bits only — that's just one of the two new bits.

So per step we have **4 candidates and only 1 effective constraint** (the low-bit congruence). Without further pruning the branching factor stays at 2 — and over 256 steps (we cover half of each end) that's `2^256` candidates. Untractable.

## 3. The pruning: product range

The salvage trick is to use the *value* of `c * d` (not just its low bits). We know each candidate has:

- Low `k+1` bits of `c` and `d` pinned
- High `k+1` bits of `c` and `d` pinned
- Middle `512 - 2(k+1)` bits unknown

For each candidate, we can bracket `c` and `d`:

```
c_min = (low bits) + 0 << (k+1)
c_max = (low bits) + (high bits) << (511 - k) + (2^(512 - 2(k+1)) - 1) << (k+1)
```

(and analogously for `d`). Then `c * d` must lie in `[c_min * d_min, c_max * d_max]`. If `n2` is outside this interval, the candidate is impossible — prune it.

The product-range estimate is rough but tightens quickly as more bits become known. Running it every step is wasteful; **every 8 steps** is a good cadence empirically. After each pruning pass the candidate count stays around ~300, instead of doubling per step.

```python
def prune_by_range(cands, n, low_bits_known, high_bits_known, total_bits):
    survivors = []
    middle_bits = total_bits - low_bits_known - high_bits_known
    for c, d in cands:
        c_lo = c & ((1 << low_bits_known) - 1)
        c_hi = c >> (total_bits - high_bits_known)
        # construct min/max of c with middle filled by 0 and (2^middle - 1)
        c_min = c_lo | (c_hi << (total_bits - high_bits_known))
        c_max = c_min | (((1 << middle_bits) - 1) << low_bits_known)
        # same for d
        ...
        if c_min * d_min <= n <= c_max * d_max:
            survivors.append((c, d))
    return survivors
```

After 256 lifting steps (covering all 512 bits since we work both ends), candidates converge to the unique solution.

## 4. Full skeleton

```python
def solve_part2(n2, x2, nbits=512):
    cands = [(0, 0)]   # (c, d) pairs, both 0 to start
    for k in range(nbits // 2):
        new = []
        for c, d in cands:
            for c_lo in (0, 1):
                for c_hi in (0, 1):
                    c2 = c | (c_lo << k) | (c_hi << (nbits - 1 - k))
                    # x2 = c XOR reverse_bits(d), so:
                    #   bit k of d corresponds to bit (nbits-1-k) of c XOR x2
                    #   bit (nbits-1-k) of d corresponds to bit k of c XOR x2
                    x2_lo_corr = (x2 >> (nbits - 1 - k)) & 1
                    x2_hi_corr = (x2 >> k) & 1
                    d_lo_bit = c_hi ^ x2_lo_corr
                    d_hi_bit = c_lo ^ x2_hi_corr
                    d2 = d | (d_lo_bit << k) | (d_hi_bit << (nbits - 1 - k))
                    if (c2 * d2) % (1 << (k+1)) == n2 % (1 << (k+1)):
                        new.append((c2, d2))
        cands = new
        # prune every 8 steps
        if k % 8 == 7:
            cands = prune_by_range(cands, n2, k+1, k+1, nbits)
    return [(c, d) for c, d in cands if c * d == n2]

# Part 1
A, B = solve_part1(n1, x1, 512)[0]   # solver returns 1-2 candidates; pick valid prime pair

# Part 2
C, D = solve_part2(n2, x2, 512)[0]

from hashlib import md5
print("flag{" + md5(str(A+B+C+D).encode()).hexdigest() + "}")
```

(`solve_part1` is the simpler version from §1.)

## 5. Traps and lessons learned

| Trap | Why it cost me time | Resolution |
|---|---|---|
| Skipped pruning in Part 2 | Assumed the mod-2^k congruence alone would converge like in Part 1 | One constraint, two new bits per step → branching at 2. Without product-range pruning, candidate count doubles indefinitely |
| Pruned every step | Wasted CPU on tight intervals that barely change | Every 8 steps is a sweet spot. The interval shrinks roughly linearly with bits known, so frequent pruning has diminishing returns |
| Confused bit ordering of `reverse_bits` | The challenge's `reverse_bits` was 512-bit specifically; I used a 1024-bit-wide reverse and got nothing | Always derive bit-reversal width from the modulus size (`n.bit_length()`-rounded-up), not assumed defaults |
| Treated `solve_part1` output as unique | It can return 2 candidates (one is `(a, b)`, one is `(b, a)`) | Add a primality check or `a < b` ordering to pick the canonical pair |
| Lost precision in interval bounds | Used floating-point estimates for `c_max * d_max` and missed valid candidates | Stay in arbitrary-precision integers throughout; Python handles this natively |

## 6. Methodology takeaways

1. **`(n, x)` where `n = a*b` and `x = a XOR b` is solvable bit-by-bit modulo `2^k`.** This is a classic — once seen, instantly recognisable. The product congruence is the single most important verification at each lift step.
2. **Bit reversal in cryptanalysis couples LSB↔MSB.** Whenever you see `reverse_bits` in a CTF crypto challenge, expect a two-ended solver. Single-ended lifting will not work.
3. **Product-range pruning is the standard rescue when constraints don't fully determine branching.** Whenever per-step branching exceeds per-step constraint count, look for a value-based (interval, modular, gcd) pruning to compensate.
4. **Cadence matters in iterative pruning.** Cheap predicate at every step + expensive predicate every N steps is a common pattern. Tune by profiling, not by guessing.
5. **Build solvers around the unknown structure, not around generic search.** A blind `itertools.product([0,1], repeat=512)` is `2^512` candidates. A structured solver that respects the equation is `~512` steps with bounded fan-out per step.

## 7. Related techniques

- **Hensel lifting** (lifting solutions from `Z/p^k Z` to `Z/p^(k+1) Z`) — this problem is a binary analogue.
- **Coppersmith's small-roots method** — useful when bit-by-bit fails because the constraint isn't `mod 2^k` shaped.
- [`how2sage` lifting tutorials](https://github.com/jvdsn/crypto-attacks) — practical implementations of related ideas.
