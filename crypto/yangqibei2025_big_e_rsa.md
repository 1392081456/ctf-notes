---
type: source
created: 2026-05-11
updated: 2026-05-11
related: []
---

# 央企杯 2025 big_e_rsa

非标准 RSA：`phi_N = (p²+p+1)(q²+q+1)`（Eisenstein 整数环阶），`d = N^0.31` 由 53-bit 浮点运算生成。攻击者用相同精度 `float(N)**0.31` 直接恢复 d，进而分解 N。

涉及概念：[[concepts/rsa-float-precision-d-recovery]], [[concepts/eisenstein-rsa-phi]]
涉及实体：[[entities/ctf_nssctf]]

## 挑战

```python
N = p * q
phi_N = (p**2 + p + 1) * (q**2 + q + 1)
d = Integer(N)**RR(0.31)   # SageMath 53-bit precision
e = inverse(Integer(d), phi_N)
flag = 'flag{' + md5(str(p+q).encode()).hexdigest() + '}'
```

给定 e, N，求 flag。

## 解法

1. `RR(0.31)` = IEEE 754 double，Python `float(N)**0.31` 完美复现 → 直接得 d
2. `e*d - 1 = k * phi_N`，`k ≈ (e*d-1)/N²` 精确整除 → 得 phi_N
3. 由 `phi_N = N² + (N+1)s + s² - N + 1` 解二次方程得 `s = p+q`
4. 由 `s, N` 解出 p, q → md5(str(p+q)) 得 flag

## Flag

```
flag{5e04df378c2b53cfabb357bab51796db}
```

## 踩坑

- Wiener 连分数对 `e/N²` 失败：`phi_N - N²≈ N^1.5` 误差破坏收敛条件
- d = N^0.31 > Boneh-Durfee 0.292 界，格攻击也不直接适用
- 真正漏洞是 d 的生成可复现，与密码学强度无关
