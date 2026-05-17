# Wangding Cup 2020 Qinglong — jocker: SMC and Stack-Pointer Repair

> **Flag**: `flag{d07abccf8a410cb37a}`
>
> **Pipeline**: 32-bit Windows PE with three layered checks:
> 1. A printable "fake flag" sitting in `unk_4030C0`, decoded by an alternating XOR/ADD over the index.
> 2. An `encrypt` function that is **encrypted in place** in `.text` — IDA can't read it until the program runs the SMC routine. Recovering it requires unpacking the bytes (or single-stepping past the SMC), then **fixing IDA's stack-pointer analysis** so the decompiler will produce pseudocode.
> 3. A `finally` function (also SMC-protected) that checks 5 trailing bytes against an XOR key derived from `'}' ^ ':'`.
>
> Three techniques to recover the encrypted code: IDA dynamic debugging + Keypatch, an IDAPython patch script, and OllyDbg dump. I ended up using all three and the IDAPython approach was the fastest by a long shot.

## 0. File overview

| Field | Value |
|---|---|
| File | `attachment.exe` |
| Format | PE32 (x86, 32-bit) |
| Compiler | MSVC |
| Notable import | `VirtualProtect` (a strong SMC indicator) |

The `VirtualProtect` import alone is enough to suspect SMC — there's almost no legitimate reason for a small CTF binary to be flipping memory page permissions at runtime.

## 1. Static survey

Functions visible in IDA after initial load:

- `wrong` — prints failure message
- `omg` — prints success message
- `finally` — final check (initially **encrypted** — Hex-Rays refuses to decompile)
- `encrypt` — main check (initially **encrypted** — same problem)

Strings worth noting:

- `"come here"`, `"wrong ~"`, `"hahahaha_do_you_find_me?"` (the last one looks suspiciously like a candidate XOR key)
- A pile of bytes in `unk_4030C0` and `unk_403040` (data for the checks)

Trying F5 on either `encrypt` or `finally` produces:

```
// positive sp value has been detected, the output may be wrong!
```

…with garbage pseudocode. That's two layers stacked: the function bytes are encrypted (so the disassembly is nonsense), AND once decrypted, the resulting code triggers IDA's stack-frame analysis bug.

## 2. Stage 1 — the fake flag in `unk_4030C0`

Before tackling the encrypted functions, the simplest check is the first one. `unk_4030C0`:

```
0x66, 0x6B, 0x63, 0x64, 0x7F,
0x61, 0x67, 0x64, 0x3B, 0x56,
0x6B, 0x61, 0x7B, 0x26, 0x3B,
0x50, 0x63, 0x5F, 0x4D,
0x00, 0x00, 0x00, 0x5A, 0x00, 0x00, 0x00,
0x71, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00,
0x37, 0x00, 0x00, 0x00, 0x66, 0x00, 0x00, 0x00
```

The trailing bytes are stored as DWORDs (those `0x00 0x00 0x00` runs); IDA defined the array as `dd` rather than `db` for the second half. After stripping zero pads, the meaningful sequence is:

```python
u = [0x66, 0x6B, 0x63, 0x64, 0x7F, 0x61, 0x67, 0x64, 0x3B, 0x56,
     0x6B, 0x61, 0x7B, 0x26, 0x3B, 0x50, 0x63, 0x5F, 0x4D,
     0x5A, 0x71, 0x0C, 0x37, 0x66]
```

The check applies an alternating transform: XOR with `i` for even indices, ADD `i` for odd indices.

```python
fake = []
for i, b in enumerate(u):
    if i & 1:
        fake.append(chr(b + i))
    else:
        fake.append(chr(b ^ i))
print("".join(fake))
# flag{fak3_alw35_sp_me!!}
```

`flag{fak3_alw35_sp_me!!}` — the **fake** flag. Note the pun: `"alw35_sp_me!!"` is "always sp me", a wink at the upcoming "sp value has been detected" decompiler error. The author is telling you straight up that the real solve involves fixing IDA's stack-pointer analysis.

If you submit this string, the binary politely tells you it's wrong and goes on to do the real check.

## 3. Stage 2 — the encrypted `encrypt` function

Both `encrypt` and `finally` live in `.text` but their bytes are XOR'd. The decryption code is in a small SMC routine that runs early in `main`:

```c
// pseudocode for the SMC stub
DWORD old;
VirtualProtect((LPVOID)0x401500, 187, PAGE_EXECUTE_READWRITE, &old);
for (int i = 0; i < 187; i++)
    *(BYTE*)(0x401500 + i) ^= 0x41;
VirtualProtect((LPVOID)0x401500, 187, old, &old);
```

So the encrypted function starts at `0x401500`, runs for 187 bytes, and is XOR'd with `0x41`.

Three ways to recover the real bytes — pick one based on what's already open and how lazy you're feeling.

### 3.1 Method A — IDA dynamic debug + manual reanalyze

1. Set a breakpoint **after** the SMC loop completes (so all 187 bytes are decrypted in memory).
2. Run the binary, type the fake flag (`flag{fak3_alw35_sp_me!!}`) so the program reaches the SMC stub.
3. Hit the breakpoint; the bytes at `0x401500` are now plaintext.
4. Select the range `0x401500 - 0x4015BB`, press **U** (undefine), then **P** at `0x401500` (re-create function from header).
5. F5 still fails because of the sp analysis issue (next section). But the disassembly is now correct.

Alternative entry: use **Keypatch** to skip past the input prompt and force execution to fall into the SMC branch directly.

### 3.2 Method B — IDAPython patch (fastest)

You don't need to run the binary at all. Mirror the SMC transform statically:

```python
# In IDA: Shift+F2 to open the script editor
import idc

addr = 0x401500   # encrypt's encrypted body
size = 187

for i in range(size):
    b = idc.get_bytes(addr + i, 1)
    idc.patch_byte(addr + i, ord(b) ^ 0x41)
```

Run, then select the range, **U**, **P**. Done.

This is the right move 95% of the time — pure static, no debugger, repeatable.

### 3.3 Method C — OllyDbg dump

Open in OllyDbg, locate the `encrypt` function via the smart string search plugin ("中文搜索引擎"), set a breakpoint on the call instruction targeting `0x401500`, F7 step into. Memory bytes are now decrypted; dump the section and reload into IDA.

I tried this and got stuck halfway — the section references didn't match what I expected from the static view. Method B is faster anyway, so I bailed.

## 4. Stage 3 — fixing the sp-analysis error

After methods A or B, the bytes at `0x401500` disassemble correctly. But F5 still produces:

```
// positive sp value has been detected, the output may be wrong!
```

…and garbage pseudocode. Why?

IDA's decompiler tracks the stack pointer (`esp`) symbolically through every instruction. If the difference between expected and actual `esp` changes across a function call, IDA flags "sp analysis failed". This typically happens when:

1. A function is called with a **non-`__cdecl` calling convention** that the decompiler can't infer (`__stdcall` callee that doesn't match the caller's expectation, for example).
2. Compiler optimization replaced a `call ... ; ret` pair with `mov esp, ebp ; pop ebp ; jmp target` (tail call), confusing the function-end heuristic.
3. Anti-disassembly instrumentation pushes onto the stack outside any function frame.

For this binary it's case 1: `encrypt` and `finally` are called via `call` instructions where IDA can't reconcile the post-call stack adjustment.

The fix is manual: at each suspicious `call`, press **Alt+K** in IDA and set the **stack delta** (the diff between old and new `sp`) to the correct value — usually 0 if the callee cleans up its own arguments.

For this challenge, the two `call encrypt` and `call finally` instructions both need their sp delta set to 0. After that, F5 produces clean pseudocode:

```c
int __cdecl encrypt(char *a1) {
    int v2[19];
    int v3 = 1;
    int i;

    qmemcpy(v2, &unk_403040, sizeof(v2));
    for (i = 0; i <= 18; ++i) {
        if ((char)(a1[i] ^ Buffer[i]) != v2[i]) {
            puts("wrong ~");
            v3 = 0;
            exit(0);
        }
    }
    puts("come here");
    return v3;
}
```

So `encrypt` checks 19 bytes: `a1[i] ^ Buffer[i] == v2[i]`. With:

- `Buffer = "hahahaha_do_you_find_me?"` (24 chars; only the first 19 are used here)
- `v2` = `unk_403040` after stripping the DWORD zero pads:

  ```
  [14, 13, 9, 6, 19, 5, 88, 86, 62, 6, 12, 60, 31, 87, 20, 107, 87, 89, 13]
  ```

Inverting: `a1[i] = Buffer[i] ^ v2[i]` →

```python
buf = b"hahahaha_do_you_find_me?"
v2  = [14, 13, 9, 6, 19, 5, 88, 86, 62, 6, 12, 60, 31, 87, 20, 107, 87, 89, 13]
print("".join(chr(buf[i] ^ v2[i]) for i in range(len(v2))))
# flag{d07abccf8a410c
```

That's 19 bytes. The full flag is 24 (closing `}` is byte 24), so 5 bytes are still missing — that's what `finally` is for.

## 5. Stage 4 — the `finally` function

`finally` is the second SMC-encrypted function. Apply Method B again, plus another round of Alt+K. The decompiled body checks the trailing 5 input bytes against:

```c
char tail[] = {'%', 't', 'p', '&', ':'};   // string literal: "%tp&:"
char key   = '}' ^ ':';                     // = 0x47

for (int i = 0; i < 5; i++)
    if ((tail[i] ^ key) != input[19 + i])
        wrong();
```

So the last 5 bytes of input must equal `tail[i] ^ ('}' ^ ':')`. The trick: the author leaks the `}` character via the XOR key. You can recognise it because the last byte of any flag is always `}`, and the last byte of `tail` is `:`. So `key = '}' ^ ':' = 0x47`, and applying it to the rest of `tail` gives the missing chars + `}`:

```python
key = ord('}') ^ ord(':')      # 0x47
tail = "%tp&:"
print("".join(chr(ord(c) ^ key) for c in tail))
# b37a}
```

## 6. Putting it together

```
flag{d07abccf8a410c        (encrypt's 19 bytes)
                  b37a}    (finally's 5 bytes)

= flag{d07abccf8a410cb37a}
```

Solve script:

```python
# Stage 2: encrypt — first 19 bytes
buf = b"hahahaha_do_you_find_me?"
v2  = [14, 13, 9, 6, 19, 5, 88, 86, 62, 6, 12, 60, 31, 87, 20, 107, 87, 89, 13]
part1 = "".join(chr(buf[i] ^ v2[i]) for i in range(len(v2)))

# Stage 4: finally — trailing 5 bytes
key  = ord('}') ^ ord(':')
tail = "%tp&:"
part2 = "".join(chr(ord(c) ^ key) for c in tail)

print(part1 + part2)
# flag{d07abccf8a410cb37a}
```

(For completeness, stage 1's fake-flag check just confirms input handling before triggering the SMC; it doesn't enter into the real flag derivation.)

## 7. What I learned

1. **`VirtualProtect` import is a giveaway.** A small CTF binary that imports `VirtualProtect` is almost certainly doing SMC. Always check imports before reading code — it saves time chasing dead-end pseudocode.
2. **"Positive sp value detected" is fixable, not fatal.** IDA's sp-analysis errors are about the decompiler's frame tracking, not about the disassembly. Walk the function's `call` / `ret` / `jmp` and use **Alt+K** to set stack deltas at the offending instructions. The disassembly view is usually correct even when F5 isn't.
3. **IDAPython is the fastest SMC unwrapper.** Anything you can express as a transform on bytes can be replayed offline. Don't bother with the debugger if you can read the SMC stub in the static binary.
4. **Watch for DWORD-stored bytes.** `unk_4030C0` and `unk_403040` looked padded with zeros, but they were actually 32-bit ints with each meaningful byte in the LSB. Always check the type IDA assigned (`db` vs `dd`) before counting elements.
5. **The author signaled the trick in the fake flag.** `"alw35_sp_me!!"` decodes to "always sp me" — telling you to fix sp analysis. CTF authors love planting hints in failure messages and dummy strings; read them carefully before going on a wild goose chase.

## 8. Anti-RE technique cheatsheet

| Technique | Indicator | Defeat |
|---|---|---|
| **SMC** (self-modifying code) | `VirtualProtect` import; opaque bytes that don't disassemble; small XOR/ADD loop touching `.text` | IDAPython replay the transform; or breakpoint after the SMC and reanalyze |
| **Stack-frame anti-decompile** | "positive sp value detected"; F5 produces garbage | Alt+K at offending calls; set delta to 0 (or whatever balances the frame) |
| **Anti-debug via `IsDebuggerPresent` / `CheckRemoteDebuggerPresent`** | API import + boolean check | Patch the check or set the PEB flag manually |
| **Anti-debug via SEH + `DebugBreak`** | Try/except wrapping `DebugBreak()` | Read the SEH scope table statically; emulate the handler offline |
| **VM / virtualization obfuscation** | Large dispatch loop with opcode table | Identify the VM bytecode format, write a disassembler |

## 9. Tools

- IDA Pro 9.x (with IDAPython)
- OllyDbg as a backup (didn't end up using it for this challenge)
