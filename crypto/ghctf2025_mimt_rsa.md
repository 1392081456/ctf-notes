---
type: source
created: 2026-05-12
updated: 2026-05-12
related: []
---

# GHCTF2025 MIMT_RSA (NSSCTF)

36-bit 合数 KEY 经 RSA 加密，利用 RSA 乘法同态性 `(a*b)^e = a^e * b^e` 做 Meet-in-the-Middle 恢复 KEY。小因子建表，大因子搜索。

涉及概念：[[concepts/rsa-mitm-factored-message]]
涉及实体：[[entities/ctf_nssctf]]

## 挑战

```python
KEY  # 36-bit composite
ck = pow(KEY, e, n)  # e=65537, n=2048-bit
flag = md5(str(KEY))
```

## 解法

1. KEY = p * q，`ck = p^e * q^e mod n`（乘法同态）
2. 表：`{pow(p, e, n): p}` for p ∈ [2, 2^18]
3. 搜索：q 从 2^18 开始，`ck * pow(q, -e, n) mod n` 查表
4. 找到 KEY = 103004 × 606733 = 62495925932
5. C + GMP 实现，约 60 秒

## Flag

```
NSSCTF{14369380f677abec84ed8b6d0e3a0ba9}
```

## 踩坑

- 对称 MITM（双方 ≤ 2^18）失败：大因子 606733 > 2^18
- Python modpow 太慢，必须用 C/GMP
