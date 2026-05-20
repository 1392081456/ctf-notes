---
type: source
created: 2026-05-13
updated: 2026-05-16
related: []
---

# SUCTF 2018 stack (BUUCTF)

64-bit ELF，No Canary / No PIE / NX off。极简栈溢出题：`buf[32]` 但 read 0x30 字节，溢出 16 字节恰好覆盖 saved RBP + return address。程序中存在后门 `next_door() = system("/bin/sh")` 在 0x400676，直接 ret 到 backdoor。

涉及概念：[[concepts/ret2win-backdoor-discovery]]、[[concepts/stack-alignment-push-rbp-skip]]
涉及实体：[[entities/ctf_buu]]

## 挑战

## 关键点

1. **侦察发现 backdoor**：`readelf -s | grep system` 看到 system 被导入；`objdump -d | grep system@plt` 找到调用点 0x400684；IDA 反编译该函数发现 `system("/bin/sh")`
2. **栈对齐 +1 技巧**：直接跳 next_door 入口会因 `push rbp` 偏 8 字节导致 system 内部 movaps 崩溃。跳 `next_door + 1` 跳过 push rbp 保持对齐

## Payload

```python
b'A' * 0x20 + b'B' * 8 + p64(0x400676 + 1)
```

