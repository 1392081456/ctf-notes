---
type: source
created: 2026-05-13
updated: 2026-05-16
related: []
---

# ACTF 2019 babyheap (BUUCTF)

64-bit ELF，Full RELRO / Canary / NX / **No PIE**。glibc 2.27。菜单题：add 创建 chunk 对 (元数据 A + 数据 D)，delete 释放但**不清空指针**（UAF），show 调用 A 中函数指针。程序自带 `system("date")` 调用，**system@PLT 已解析**，无需 leak libc 即可调用 system，但需要 leak libc 获取 "/bin/sh" 地址。

涉及概念：[[concepts/uaf-funcptr-tcache-reuse]]、[[concepts/printf-percent-s-leak-via-got]]
涉及实体：[[entities/ctf_buu]]、[[entities/lib_glibc-2.27]]

## 挑战

## 漏洞链

### UAF 触发条件
- `delete` 顺序释放 D 和 A，但 `ptr[i]` 未清零
- 释放后 `ptr[i]` 仍指向 A，可通过 show 再次调用 A+8 的函数指针

### 关键 size 选择
- add 中 A 总是 `malloc(0x10)` → chunk 0x20
- D 是 `malloc(size)`：当 size=0x20 时 D 为 chunk 0x30，进入不同 tcache bin
- 当 size=0x10 时 D 也是 chunk 0x20，从 tcache 0x20 取 → **A 可以被复用为新 chunk 的 D**

### 利用步骤

**Stage 1 — libc 泄露**：
1. add(0..2, 0x20, ...)，free(0), free(1)
2. tcache 0x20 head = A1 → A0
3. add(_, 0x10, p64(system@GOT)):
   - malloc(0x10) 拿 A1 → ptr[3]=A1, A1+8 写为 sub_40098A
   - malloc(0x10) 拿 A0 → A1+0 = A0
   - read 8 字节 p64(system@GOT) 写入 A0 → A0+0 = system@GOT, A0+8 不变 (sub_40098A)
4. show(0): ptr[0]=A0 (UAF), 调用 `sub_40098A(*A0) = printf("Content is '%s'", system@GOT)` → 输出 libc 中 system 实际地址

**Stage 2 — getshell**：
1. free(3), 再 add(_, 0x10, p64(bin_sh)+p64(system@PLT)):
   - A1, A0 复用，read 16 字节写入 A0
   - A0+0 = str_bin_sh, A0+8 = system@PLT
2. show(0): 调用 `*(A0+8)(*A0) = system("/bin/sh")` → getshell

## 关键技巧

- **read 不修改 A+8**：第一次 8 字节 read 只覆盖 A+0，保留 A+8 = sub_40098A 用于 printf 解引用 GOT
- **printf %s 作为 leak primitive**：`%s` 把 8 字节指针作为字符串地址解引用，自然 leak libc
- **System@PLT 已解析**：程序自身有 `system("date")` 调用，无需手动写 system 地址

