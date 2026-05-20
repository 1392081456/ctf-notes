---
type: source
created: 2026-05-13
updated: 2026-05-16
related: []
---

# UTCTF2020 basic-crypto

四层编码洋葱题，逐层剥开：Binary → Base64 → Caesar(ROT10) → Substitution Cipher。每层解码后有英文提示指向下一层编码方式。

涉及概念：[[concepts/multi-layer-encoding-peel]]、[[concepts/substitution-cipher-known-plaintext]]

## 挑战

## 解题路径

1. **Binary → ASCII**：空格分隔的 8-bit 二进制转字符，得到提示"字符集只有 A-Z, a-z, 0-9, /, +"
2. **Base64 解码**：标准 Base64，得到提示"letters shifted by constant" + "Roman people"
3. **Caesar ROT10**：遍历 26 种偏移，shift=16 解出可读文本，提示"substitution cipher"
4. **Substitution Cipher**：已知 flag 格式 `utflag{...}` 对应密文 `vtsoid{...}` 建立初始映射 6 对，再用英文频率分析 + 上下文推导剩余映射

## 关键技术

- 已知明文攻击：flag 格式提供 6 个字母映射作为突破口
- 频率分析：`tya`→`the`、`jk`→`is` 等高频词快速扩展映射表
- 逐层提示：每层解码结果包含下一层的 hint，降低难度

## Flag

```
utflag{n0w_th4ts_wh4t_i_c4ll_crypt0}
```

