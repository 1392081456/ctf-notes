---
type: source
created: 2026-05-11
updated: 2026-05-11
related: []
---

# npuctf_2020_easyheap (BUUCTF)

glibc 2.27 堆题。edit 中 `read_input(buf, size+1)` 导致 off-by-one，覆盖相邻 chunk 的 size 域。通过两次独立 overlapping（leak + write）分别泄露 libc 和写 `__free_hook`。

涉及概念：[[concepts/heap-off-by-one-overlapping]]、[[concepts/tcache-uaf-funcptr-overwrite]]
涉及实体：[[entities/ctf_buu]]、[[entities/lib_glibc-2.27]]

## 挑战

64-bit ELF，glibc 2.27。每次 create 产生 `[Node(0x20)] + [Content(0x20 或 0x40)]` 连续排列。edit 的 `read_input` 多读 1 字节。

## 漏洞

Content 的 off-by-one 溢出 1 字节到下一个 chunk 的 SIZE 域 LSB（不是 prev_size）。

## 利用策略：两次独立 overlapping

不要试图一次完成 leak + write，用两个独立的 victim pair。

### 第一次 overlapping（leak）

1. Content(24B) → chunk 0x20，off-by-one 覆盖相邻 Node(0x20) 的 size 从 0x21 改为 0x41
2. delete 该 Node → 进 tcache 0x40
3. create(size=56) → malloc(0x40) 拿到这个 Node → Content 和 Node 内存重叠
4. 重叠后 Content[32:40] = Node->size，Content[40:48] = Node->content_ptr
5. 设 content_ptr = puts@got → show 泄露 libc

### 第二次 overlapping（write）

同手法对第二个 pair → 控制 content_ptr = `__free_hook` → edit 写 `system` → free("/bin/sh")

## 关键细节

- 小 Content(24B) → chunk 0x20；大 Content(56B) → chunk 0x40
- off-by-one payload: `padding*56 + b'\x41'`（57 字节）
- overlapping 时 create(size=56) 的 payload: `padding*32 + p64(new_size) + p64(target_addr) + padding*8`
- write `__free_hook` 时 edit 只发 `p64(system_addr)`（8 字节），多写会破坏后面的 libc 数据
- delete 后 create 会填第一个 NULL slot（不是按数字顺序）

## 踩坑

- 第一次 overlapping leak 后，如果直接 delete 该 entry 会 `free(puts_got)` → crash
- 必须用第二个独立 pair 做 write
