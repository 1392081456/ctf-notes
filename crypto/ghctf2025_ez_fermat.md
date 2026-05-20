---
type: source
created: 2026-05-12
updated: 2026-05-12
related: []
---

# GHCTF2025 EZ_Fermat (NSSCTF)

RSA + 多项式提示 `w = 2^f(p) mod n`。利用费马小定理 `p ≡ 1 (mod p-1)` 推出 `f(p) ≡ f(1) (mod p-1)`，从而 `gcd(w·2^(-f(1)) - 1, n) = p`。

涉及概念：[[concepts/fermat-polynomial-gcd-factor]]
涉及实体：[[entities/ctf_nssctf]]

## 挑战

```python
w = pow(2, f(p), n)  # f 是 332 次小系数多项式
```

给定 n, e, c, f, w，求 flag。

## 解法

1. 费马小定理：`2^(p-1) ≡ 1 (mod p)`
2. `p ≡ 1 (mod p-1)` → `f(p) ≡ f(1) (mod p-1)`
3. `w ≡ 2^f(1) (mod p)`
4. f(1) = -57 → `p = gcd(w * 2^57 - 1, n)`
5. 标准 RSA 解密

## Flag

```
NSSCTF{8d1e3405044a79b23a44a43084bd994b}
```
