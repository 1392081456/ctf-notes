---
type: source
created: 2026-05-12
updated: 2026-05-12
related: []
---

# GHCTF2025 mybrave (NSSCTF)

ZipCrypto STORED 加密 ZIP，bkcrack 已知明文攻击（PNG 文件头）恢复密钥 → PNG IEND 后 UTF-16LE 编码 Base64 隐写。

涉及概念：[[concepts/bkcrack-known-plaintext-attack]]
涉及实体：[[entities/ctf_nssctf]]

## 挑战

加密 ZIP 内含一张 PNG 图片，无其他提示。

## 解法

1. ZipCrypto + STORED → bkcrack 已知明文攻击（PNG 16 字节文件头）
2. 约 10 分钟恢复内部密钥：`97d30dcc 173b15a8 6e0e7455`
3. 解密得到 PNG，exiftool 发现 IEND 后有 trailer data
4. Trailer 160 字节 = UTF-16LE 编码的 Base64 → 解码得 flag

## Flag

```
NSSCTF{I'm_Wh1sp3riNg_OuR_Lu11abY_f0r_Y0u_to_CoMe_B4ck_Home}
```

## 踩坑

- 尝试字典爆破/伪加密均失败，必须用 bkcrack
- Trailer 数据是 UTF-16LE 不是 ASCII，需注意每隔一字节的 0x00
