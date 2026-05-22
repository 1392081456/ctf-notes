---
type: source
created: 2026-05-13
updated: 2026-05-16
related: []
---

# ACTF 2019 babystack (BUUCTF)

64-bit ELF，No Canary / No PIE / NX。栈缓冲区 0xD0 字节但允许读入 0xE0 字节（溢出 16 字节），程序主动泄露缓冲区栈地址。利用栈迁移（stack pivot）将 RSP 迁移到缓冲区中执行完整 ROP 链。

涉及概念：[[concepts/stack-pivot-leave-ret]]、[[concepts/ret2libc-two-stage]]
涉及实体：[[entities/ctf_buu]]、[[entities/lib_glibc-2.27]]

## 挑战

## 漏洞

`read(0, s, nbytes)` 中 nbytes 上限 0xE0，缓冲区 s 仅 0xD0 字节，溢出 0x10 字节恰好覆盖 saved RBP + return address。

## 利用路径

1. 程序泄露 `s` 的栈地址
2. Stage 1：缓冲区布置 `pop rdi + puts@GOT + puts@PLT + main` ROP 链，覆盖 saved RBP 为缓冲区地址，ret 为 `leave;ret` → 栈迁移 → 泄露 puts 真实地址 → 返回 main
3. Stage 2：计算 libc 基址，缓冲区布置 `ret + pop rdi + "/bin/sh" + system` → 栈迁移 → getshell

## 关键技术

- **栈迁移**：溢出量不足时，覆盖 saved RBP 为目标地址 + ret 为 `leave;ret`，使 RSP 跳转到可控内存
- `leave` = `mov rsp, rbp; pop rbp`，连续两次 leave 实现 RSP 重定向
- 16 字节对齐：Stage 2 加一个 `ret` gadget 保证 system 调用时栈 16 字节对齐

