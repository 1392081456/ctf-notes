---
type: source
created: 2026-05-12
updated: 2026-05-12
related: []
---

# GHCTF2025 baby_signin (NSSCTF)

RSA e=4 且 gcd(e, φ(n))=4，标准解密不存在。已知 p, q，用 Tonelli-Shanks + CRT 逐层开平方根恢复明文。

涉及概念：[[concepts/rsa-non-coprime-e-amm]]
涉及实体：[[entities/ctf_nssctf]]

## 挑战

```python
e = 4
c = pow(m, e, n)  # p, q, c, n 全部给出
```

## 解法

1. gcd(4, φ) = 4 → 无模逆 d
2. 对 c 逐层开平方根（mod p, mod q），CRT 组合
3. 8 个候选中筛选出 ASCII flag

## Flag

```
NSSCTF{4MM_1s_so_e4s7!}
```
