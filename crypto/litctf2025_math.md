# LitCTF 2025 — math: RSA with `hint = (p+noise)(q+noise)` leak

> The challenge gives `n = pq`, ciphertext `c`, and `hint = (p+noise)(q+noise)` where `noise` is a 40-bit prime. The trick is to notice that `hint - n` is divisible by `noise` and that `noise` is small enough to surface via Pollard's rho on the difference. Once `noise` is recovered, Vieta gives `p` and `q` immediately.

## Challenge (`task.py`)

```python
from Crypto.Util.number import *
from enc import flag

m = bytes_to_long(flag)
e = 65537
p, q = getPrime(1024), getPrime(1024)
n = p*q
noise = getPrime(40)
tmp1 = noise*p + noise*q
tmp2 = noise*noise
hint = p*q + tmp1 + tmp2          # ← the leak
c = pow(m, e, n)
```

`n`, `e`, `c`, `hint` are printed.

## 1. Algebra (the 30-second observation)

```
hint = pq + noise·p + noise·q + noise²
     = pq + noise(p + q + noise)

⇒ hint - n = noise · (p + q + noise)
```

Let `D = hint - n`. Then `noise | D` and `noise` is a 40-bit prime.

`D` is roughly 1065 bits (`noise` is 40 bits, `p+q+noise` is ~1025 bits) — too big to trial-divide, but Pollard's rho will find the 40-bit factor in microseconds because rho's expected work scales as √(smallest prime factor) ≈ 2²⁰.

## 2. Recovery

```python
D = hint - n                  # 1065 bits

# Trial-divide tiny primes first (this particular D has 19 as a factor of (p+q+noise))
M = D
for p_small in range(2, 10**6):
    while M % p_small == 0:
        M //= p_small

# Pollard rho on the remainder → finds the 40-bit noise
noise = pollard_rho(M)        # → 942430120937 (40 bits)

p_plus_q = D // noise - noise # since D = noise * (p+q+noise)
disc     = p_plus_q**2 - 4*n  # Vieta: x² - (p+q)x + pq = 0
sq       = isqrt(disc)
p, q     = (p_plus_q + sq)//2, (p_plus_q - sq)//2
assert p*q == n

phi = (p-1)*(q-1)
m   = pow(c, inverse(e, phi), n)
print(long_to_bytes(m))       # → LitCTF{db6f52b9265971910b306754b9df8b76}
```

## 3. Full exploit

```python
from math import gcd
from Crypto.Util.number import long_to_bytes, inverse
import random

n = 17532490684844499573962335739488728447047570856216948961588440767955512955473651897333925229174151614695264324340730480776786566348862857891246670588649327068340567882240999607182345833441113636475093894425780004013793034622954182148283517822177334733794951622433597634369648913113258689335969565066224724927142875488372745811265526082952677738164529563954987228906850399133238995317510054164641775620492640261304545177255239344267408541100183257566363663184114386155791750269054370153318333985294770328952530538998873255288249682710758780563400912097941615526239960620378046855974566511497666396320752739097426013141
e = 65537
c = 1443781085228809103260687286964643829663045712724558803386592638665188285978095387180863161962724216167963654290035919557593637853286347618612161170407578261345832596144085802169614820425769327958192208423842665197938979924635782828703591528369967294598450115818251812197323674041438116930949452107918727347915177319686431081596379288639254670818653338903424232605790442382455868513646425376462921686391652158186913416425784854067607352211587156772930311563002832095834548323381414409747899386887578746299577314595641345032692386684834362470575165392266454078129135668153486829723593489194729482511596288603515252196
hint = 17532490684844499573962335739488728447047570856216948961588440767955512955473651897333925229174151614695264324340730480776786566348862857891246670588649327068340567882240999607182345833441113636475093894425780004013793034622954182148283517822177334733794951622433597634369648913113258689335969565315879035806034866363781260326863226820493638303543900551786806420978685834963920605455531498816171226961859405498825422799670404315599803610007692517859020686506546933013150302023167306580068646104886750772590407299332549746317286972954245335810093049085813683948329319499796034424103981702702886662008367017860043529164

D = hint - n

# 1. peel any tiny factors (this D happens to have 19 | (p+q+noise))
M = D
for s in range(2, 10**6):
    while M % s == 0:
        M //= s

# 2. Pollard rho — finds the 40-bit prime quickly because complexity ~ O(p^0.5)
def pollard_rho(N):
    while True:
        x = random.randrange(2, N)
        c = random.randrange(1, N)
        y, d = x, 1
        while d == 1:
            x = (x*x + c) % N
            y = (y*y + c) % N
            y = (y*y + c) % N
            d = gcd(abs(x - y), N)
        if d != N:
            return d

noise = pollard_rho(M)
while noise.bit_length() > 41:
    noise = pollard_rho(M)
assert D % noise == 0

# 3. Vieta on (p+q, pq) → (p, q)
p_plus_q = D // noise - noise

def isqrt(n):
    x, y = n, (n + 1) // 2
    while y < x:
        x, y = y, (y + n // y) // 2
    return x

disc = p_plus_q*p_plus_q - 4*n
sq   = isqrt(disc)
assert sq*sq == disc
p, q = (p_plus_q + sq)//2, (p_plus_q - sq)//2
assert p*q == n

# 4. textbook RSA
phi = (p-1)*(q-1)
d   = inverse(e, phi)
m   = pow(c, d, n)
print(long_to_bytes(m))
# LitCTF{db6f52b9265971910b306754b9df8b76}
```

Recovered values:
- `noise = 942430120937`
- `p = 1357…36941` (1024 bits)
- `q = 1291…68201` (1024 bits)
- flag = `LitCTF{db6f52b9265971910b306754b9df8b76}`

## 4. Why this works — and where it fails

**Key insight**: any `hint = f(p, q, small)` that algebraically yields `hint − n = small · (large)` gives away `small` via factor algorithms whose runtime scales with `√(small)` rather than `√(n)`. The same trick works for these common LitCTF/HCB-style RSA puzzles:

| Leak form | What's `hint − n`? | Recover |
|---|---|---|
| `hint = (p+k)(q+k)` | `k(p+q+k)` | rho on hint−n → k |
| `hint = pq + kp + kq` | `k(p+q)` | rho on hint−n → k |
| `hint = (p+a)(q+b), a≠b` | `aq + bp + ab` | combine with another leak |
| `hint = p + q` (plus n) | given outright | Vieta directly |

**It fails when** `noise ≳ 100 bits` (rho expected work √noise becomes infeasible) — at that point you need ECM, or you need a *second* relation (e.g. `noise² mod n` leak).

## 5. Lessons learned / traps

| Trap | Why it costs time | Mitigation |
|---|---|---|
| Throwing `factorint(hint − n)` at sympy is slow without bounds | Default factorint tries trial division to 10⁵ then Pollard rho with small iter | Run trial division by hand to ~10⁶, then rho on the remainder for 2²⁴ iters max |
| The 5-bit factor 19 in `(p+q+noise)` is a herring | rho may surface 19 first and you might think "that's noise" | Filter rho output by bit-length; noise is supposed to be 40 bits |
| Buffered output via `conda run -n re python3 …` | Streaming output never appears, looks like the script hung | Use `/root/miniconda3/envs/re/bin/python3 -u script.py > log 2>&1 &` instead, or `Monitor` |
| Vieta's discriminant precision | `isqrt` in `math` works for ints, but rolling your own newton's method is safer for >2k-bit inputs | Use the standard `math.isqrt` (Python 3.8+) or write a Newton iteration |
| Assumed `noise * (p+q+noise)` factorization is complete | If `(p+q+noise)` is composite (rare but possible), rho can surface a *factor of (p+q+noise)* first | Take the smallest 40-bit factor; verify `D % noise == 0` and `p*q == n` at the end |

## 6. Related techniques

- [GKCTF 2021 XOR](gkctf2021_xor.md) — different style of RSA factor recovery: XOR + product leak instead of `(p+k)(q+k)` form
- [MRCTF 2020 Easy_RSA](mrctf2020_easy_rsa.md) — `φ(n)` and `e·d` leak → factor `n` via quadratic root, same Vieta closing move
- The "noise" framing is also called **"perturbed factorization"** in the academic literature — see Coppersmith's small-root attacks if `noise` is too big for rho but still ≤ N^(1/4)
