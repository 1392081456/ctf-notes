# SCTF 2019 — creakme: AES-CBC, Base64, and an SEH Self-Decrypting Section

> **Flag**: `sctf{Ae3_C8c_I28_pKcs79ad4}`
>
> **Pipeline**: `flag → AES-128-CBC (key="sycloversyclover", IV="sctfsctfsctfsctf") → standard Base64 → reverse + (+1 per byte) → embedded constant`.
>
> The last step (the post-Base64 obfuscation) is implemented inside an RWX section called `.SCTF` that is decrypted at runtime via a `DebugBreak()` + SEH dance. Under a debugger, the breakpoint is consumed by the debugger and the SEH never runs — so the section is never decrypted and the comparison runs against still-encrypted code. That's the anti-debug.

## 0. File overview

| Field | Value |
|---|---|
| File | `attachment.exe` |
| Format | PE32 (x86, 32-bit) |
| MD5 | `cd39c075e05b2b424432ed5e638b7432` |
| Compiler | MSVC, linked against VCRUNTIME140 / MSVCP140 |
| Image base | `0x400000` |

Sections:

| Name | Range | Perms | Notes |
|---|---|---|---|
| `.text` | `0x401000 - 0x404000` | RX | |
| `.SCTF` | **`0x404000 - 0x405000`** | **RWX** | ⚠ custom RWX section |
| `.idata` | `0x405000 - 0x405148` | R | |
| `.rdata` | `0x405148 - 0x409000` | R | |
| `.data` | `0x409000 - 0x40A000` | RW | |

A custom RWX section is suspicious by itself; one named after the CTF organiser is even more so.

## 1. Static-only first impressions

Skimming strings:

| Address | String | Note |
|---|---|---|
| `0x407374` | `sycloversyclover` (16 bytes) | candidate AES-128 key |
| `0x407360` | `sctfsctfsctfsctf` (`xmmword_407360`) | candidate IV |
| `0x409018` | `>pvfqYc,4tTc2UxRmlJ,sB{Fh4Ck2:CFOb4ErhtIcoLo` (44 bytes) | embedded "ciphertext" |
| `0x407390` | `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/` | standard Base64 alphabet |
| `0x407404` | `.SCTF` | section name string |
| `0x40740C` | `welcome to 2019 sctf` | banner |
| `0x407424` | `please input your ticket:` | prompt |
| `0x40744C` | `A forged ticket!!` | failure msg |

So at minimum: AES + Base64. But the embedded "ciphertext" `>pvfqYc,4tTc2UxRmlJ,sB{Fh4Ck2:CFOb4ErhtIcoLo` contains characters (`>`, `,`, `{`, `:`) that don't exist in the standard Base64 alphabet. Two possibilities:

1. The Base64 alphabet was modified.
2. The Base64 output was *post-processed* by something else.

Walking xrefs to `aPvfqyc4ttc2uxr` (the embedded constant) and to the Base64 alphabet at `0x407390` — the alphabet is read once and never written, so it isn't modified. That points at option 2.

## 2. main

`_main` at `0x402540`:

```c
int main(...) {
    HMODULE h = GetModuleHandleW(NULL);
    sub_402320(h);                       // ① anti-debug + decrypt .SCTF section
    sub_4024A0();                        // ② call into .SCTF code
    cout << "welcome to 2019 sctf" << endl;
    cout << "please input your ticket:";
    cin  >> Src;

    sub_401D30(v23, Src, strlen(Src));   // copy input into std::string
    v5 = sub_4020D0(...);                // ③ AES-CBC + Base64

    // ④ compare 4 bytes at a time vs aPvfqyc4ttc2uxr
    v6 = strlen(aPvfqyc4ttc2uxr);
    for (i = 0; i < min(v6, v5_len); i += 4) {
        if (v5[i..i+3] != aPvfqyc4ttc2uxr[i..i+3]) break;
    }
    ...
    cout << (success ? "Have fun!" : "A forged ticket!!");
    system("pause");
}
```

Important: ① and ② run **before** the encryption. So whatever ends up in `.SCTF` after decryption may be modifying the embedded constant or other state before the comparison happens.

## 3. Recognising AES (`sub_401690`, `sub_401070`)

### 3.1 Key schedule (`sub_401690`)

```c
*(this + 968)  = 16;                              // key length
*(this + 972)  = 16;
*(_OWORD*)(this + 980)  = xmmword_407360;         // IV stored at +980
memcpy((char*)this + 1012, &xmmword_407360, 16);  // IV ALSO stored at +1012

// Number of rounds based on key length
if (key_len == 16) Nr = 10;     // AES-128
else if (key_len == 24) Nr = 12;
else                  Nr = 14;
*(this + 976) = Nr;

// Key bytes packed into DWORDs in big-endian:
v22 = key[i*4]     << 24;
v23 = v22 | (key[i*4+1] << 16);
v24 = v23 | (key[i*4+2] << 8);
result = v24 | key[i*4+3];

// Round-key expansion uses byte_405DE0 (256-byte SBox)
```

Three classic AES indicators:

1. A 256-byte constant blob at `byte_405DE0` — the AES SBox.
2. Round count chosen from {10, 12, 14} based on key length — this is AES-128/192/256.
3. Key bytes packed into round-keys big-endian — standard AES wire format.

Round count = 10 (since key length = 16) → **AES-128**.

### 3.2 Block encryption (`sub_401070`)

The round body, for one of the four state words:

```c
state_next = round_key_word
           ^ dword_4062E0[byte0]    // Te0
           ^ dword_4051E0[byte1]    // Te1
           ^ dword_4055E0[byte2]    // Te2
           ^ dword_4059E0[byte3];   // Te3
```

Four 1 KB tables, each indexed by one byte of the previous state, all XOR'd into a 32-bit accumulator. This is the **Bertoni T-table optimisation** for AES — `SubBytes`, `ShiftRows`, `MixColumns` and one round-key XOR all collapsed into four table lookups + four XORs per word.

| Address | Size | Role |
|---|---|---|
| `0x405DE0` | 256 B | AES SBox |
| `0x4062E0` | 1 KB | Te0 |
| `0x4051E0` | 1 KB | Te1 |
| `0x4055E0` | 1 KB | Te2 |
| `0x4059E0` | 1 KB | Te3 |

Memorise this fingerprint — there is no other widespread cipher that looks like this in optimised C. The fan-in pattern `T0[b0] ^ T1[b1] ^ T2[b2] ^ T3[b3] ^ rk` is the only signal you need.

### 3.3 CBC mode (`sub_4020D0`)

```c
// PKCS#7 padding to next 16-byte boundary
v3 = 16 * ((len >> 4) + 1);          // ALWAYS adds at least one full padding block
memset(buf + len, padbyte, padlen);

// CBC main loop
while (block_idx < n_blocks) {
    for (i = 0; i < 16; i++)
        v36[i] ^= plaintext[i];          // XOR with previous ciphertext (or IV first)
    sub_4013E0(v36, output);             // AES encrypt block
    memcpy(v36, output, 16);             // current ciphertext becomes next-block XOR seed
    plaintext += 16;
    output    += 16;
}
```

XOR-with-previous-block then AES encrypt = textbook **CBC**. Note that PKCS#7 padding here always adds at least one full block — so a plaintext of length 12 produces a 32-byte ciphertext (one block of plaintext + one block of pad bytes).

### 3.4 Where is the IV?

`v36` looks like a freshly allocated 128-byte stack buffer. But cross-referencing the stack layout:

```
[ebp-58h]   v23   ← AES context object (offset 0)
...
[ebp-90h]   v36[128]   ← (ebp-90h) - (ebp-58h - 0x4) = 0x3F4 from object start
```

`0x3F4 = 1012` — and `*(this + 1012) = xmmword_407360` from the key schedule. So `v36` isn't really a fresh stack buffer; it's a member field of the AES object that's already been initialised to the IV `"sctfsctfsctfsctf"`. The decompiler shows it as a stack variable because of the way the C++ object is allocated on the stack.

Lesson: when an "uninitialised" stack buffer in a CBC loop somehow has the right initial value, check if it's actually a member of a struct/object whose start address is nearby on the stack.

## 4. Recognising Base64 (`sub_401A70`)

```c
// 3 bytes in → 4 chars out
v35 = v40[0] >> 2;
v36 = (v40[1] >> 4) | ((v40[0] & 3) << 4);
v37 = (v40[2] >> 6) | ((v40[1] & 0xF) << 2);
v38 = v40[2] & 0x3F;

// Look up in alphabet at dword_409048
output[i] = ((char*)dword_409048)[*(&v35 + i)];

// Tail padding with '=' (0x3D)
```

`dword_409048` is initialised in `sub_401000` to `"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"` — the **standard** Base64 alphabet. Searching xrefs: no other code writes to this buffer. So the alphabet is genuinely unmodified.

Confirms suspicion: the Base64 output is standard, the obfuscation is downstream.

## 5. The `.SCTF` section: anti-debug + self-decrypt

### 5.1 Trigger (`sub_402320`)

```asm
; Walk IMAGE_SECTION_HEADER table looking for ".SCTF"
mov     esi, [ecx+3Ch]                ; e_lfanew
movzx   ebx, [eax+ecx+6]              ; NumberOfSections
lea     esi, [ecx+0F8h]               ; first section header

loop_section:
    cmp     [esi], ".SCTF"             ; section.Name
    jnz     next_section
    ; Found .SCTF
    mov     [TryLevel], 0
    call    DebugBreak                  ; trigger INT3
    ; Exception is swallowed (under debugger) or handled (otherwise)
loc_4023B9:
    mov     [TryLevel], 0FFFFFFFEh
    ; function epilogue
next_section:
    add     esi, 28h
    jmp     loop_section
```

The trick: `DebugBreak()` raises `EXCEPTION_BREAKPOINT` (`0x80000003`). When a debugger is attached, the **debugger** intercepts and consumes that exception by default — the program's SEH handler never runs. So under a debugger, control returns straight to `loc_4023B9` and the function epilogue, the `.SCTF` section is never decrypted, and yet `_main` still proceeds to call into `.SCTF` and then encrypt the input. Result: the comparison is against still-encrypted code state, which never matches, and you see "A forged ticket!!" no matter what you type. Took me an evening to figure out.

### 5.2 SEH scope table

The SEH handler in this binary is `__except_handler4`. The scope table for `sub_402320` (`stru_407B58`) has two entries:

```
{enclosing=-2, filter=0,         target=0}                # default
{enclosing=-2, filter=0x4023DC,  target=0x4023EF}         # ← interesting
```

The filter at `loc_4023DC`:

```asm
loc_4023DC:                              ; filter — runs to decide if we handle
    cmp     [exception_record].ExceptionCode, 80000003h
    jnz     short reject
    mov     eax, 1
    ret
reject:
    xor     eax, eax
    ret
```

So the filter accepts only `EXCEPTION_BREAKPOINT`.

The target at `loc_4023EF` is where execution continues if the filter returns 1:

```asm
loc_4023EF:
    push    offset pbDebuggerPresent
    call    GetCurrentProcess
    push    eax
    call    CheckRemoteDebuggerPresent       ; ① remote debugger?
    call    IsDebuggerPresent                ; ② local debugger?
    test    eax, eax
    jnz     loc_4023B9                       ; debugger detected → skip decrypt
    cmp     [pbDebuggerPresent], eax
    jnz     loc_4023B9                       ; remote debugger → skip
    ; No debugger → decrypt the section
    mov     edx, [esi+10h]                   ; section.SizeOfRawData
    mov     ecx, [esi+0Ch]                   ; section.VirtualAddress
    add     ecx, image_base                  ; → 0x404000
    push    16                                ; key_len
    push    ecx
    call    sub_402450                       ; decrypt .SCTF in place
```

Two-stage anti-debug: (a) `DebugBreak()` filtering on `EXCEPTION_BREAKPOINT` (which a debugger would normally intercept), then (b) a paranoia check via `IsDebuggerPresent` + `CheckRemoteDebuggerPresent` even after the SEH path was taken.

### 5.3 Decrypt routine (`sub_402450`)

```c
void sub_402450(uint8_t *section, int key_len) {
    const char *key = "sycloversyclover";   // same string as the AES key
    int section_size = ...;
    for (int i = 0; i < section_size; i++)
        section[i] = ~(section[i] ^ key[i % key_len]);
}
```

Note: `x = ~(x ^ k)`. This is **self-inverse**: applying it twice returns the original. So encrypt and decrypt are the same function — convenient.

### 5.4 Statically applying the same transform

You don't need to debug the binary to see what `.SCTF` does. The decrypt routine is right there in `.text`; just apply it offline.

```python
import pefile

pe = pefile.PE("attachment.exe")
section = next(s for s in pe.sections if s.Name.startswith(b".SCTF"))
encrypted = section.get_data()

KEY = b"sycloversyclover"
decrypted = bytes((~(b ^ KEY[i % 16])) & 0xFF for i, b in enumerate(encrypted))
open("sctf_decrypted.bin", "wb").write(decrypted)
```

Or, since IDA was already loaded, do it inline through the MCP and disassemble in the same step:

```python
# from IDA MCP py_eval
import ida_bytes, capstone
key = b"sycloversyclover"
enc = ida_bytes.get_bytes(0x404000, 0x1000)
dec = bytes((~(b ^ key[i % 16])) & 0xFF for i, b in enumerate(enc))
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
for ins in md.disasm(dec[:200], 0x404000):
    print(f"{ins.address:08x}  {ins.mnemonic} {ins.op_str}")
```

### 5.5 What the decrypted code does

The first ~169 bytes of decrypted `.SCTF` reverse-engineer to:

```c
void __stdcall sctf_routine(void) {
    char *s   = (char*)0x409018;        // points at the embedded "ciphertext"
    int   len = strlen(s);

    // Step A: subtract 1 from each byte
    for (int edx = 0; edx < len; edx++)
        s[edx]--;

    // Step B: reverse the string in place
    int len2 = strlen(s);               // recompute (-1 might have introduced 0)
    for (int esi = 0; esi < len2 / 2; esi++) {
        char tmp = s[esi];
        s[esi]            = s[len2 - 1 - esi];
        s[len2 - 1 - esi] = tmp;
    }
}
```

So the embedded string at `0x409018` is **mutated in place** before the comparison: every byte is decremented by 1, then the whole string is reversed.

That means what `_main` actually compares against — after step ② finishes — is `reverse(byte - 1 for byte in original)`.

### 5.6 What does the actual Base64 output look like?

Inverting the post-processing on the embedded constant `>pvfqYc,4tTc2UxRmlJ,sB{Fh4Ck2:CFOb4ErhtIcoLo`:

```python
orig = b">pvfqYc,4tTc2UxRmlJ,sB{Fh4Ck2:CFOb4ErhtIcoLo"
step1 = bytes((b - 1) & 0xFF for b in orig)   # undo "byte--"
step2 = step1[::-1]                            # undo reverse
print(step2)
# b'nKnbHsgqD3aNEB91jB3gEzAr+IklQwT1bSs3+bXpeuo='
```

Now it looks exactly like a standard Base64 string — single trailing `=`, all characters in the standard alphabet. Sanity check passes.

## 6. Inverting the whole chain

```python
import base64
from Crypto.Cipher import AES

embedded = b">pvfqYc,4tTc2UxRmlJ,sB{Fh4Ck2:CFOb4ErhtIcoLo"

# Layer 4: undo "subtract 1 from each byte"
step1 = bytes((b - 1) & 0xFF for b in embedded)

# Layer 3: undo reverse
step2 = step1[::-1]
# step2 = b"nKnbHsgqD3aNEB91jB3gEzAr+IklQwT1bSs3+bXpeuo="

# Layer 2: standard Base64 (re-pad to a multiple of 4 if needed)
step3 = base64.b64decode(step2 + b"=" * (-len(step2) % 4))

# Layer 1: AES-CBC
key = b"sycloversyclover"
iv  = b"sctfsctfsctfsctf"
plain = AES.new(key, AES.MODE_CBC, iv).decrypt(step3)

# PKCS#7 unpad
flag = plain[:-plain[-1]]
print(flag)
# b'sctf{Ae3_C8c_I28_pKcs79ad4}'
```

## 7. Things I learned

1. **`DebugBreak()` + `__except` is a real anti-debug pattern, and it costs you an evening if you don't know it.** The fix is to either configure your debugger to pass `EXCEPTION_BREAKPOINT` (`0x80000003`) to the program (which you usually don't want as a debugger default), or — much faster — read the SEH handler statically and apply its transform offline.
2. **AES T-tables don't *look* like AES at first glance.** No `SubBytes`, no `ShiftRows`, no `MixColumns` matrix multiply. Everything is collapsed into four 1KB lookups XOR'd together per word. The fan-in pattern `T0[b0] ^ T1[b1] ^ T2[b2] ^ T3[b3] ^ rk` is the only signal. If you don't have it cached, it'll look like a generic table-driven cipher.
3. **The IV may be hidden inside the cipher object.** A function signature like `aes_encrypt(ctx, in, out, len)` doesn't tell you whether the IV is passed separately or stored inside `ctx`. Check what 16-byte constants are `memcpy`'d into the context during init — there are often two (key + IV).
4. **Don't stop at "looks like Base64".** Just because the next layer looks like text doesn't mean it's the final form. The post-processing here keeps the output mostly within printable range, which is camouflage. Always compare your candidate output against the real embedded constant; if it doesn't match, the chain has more layers.
5. **PKCS#7 padding always adds at least one byte.** If the plaintext length is already a multiple of 16, AES-CBC PKCS#7 still adds 16 bytes of `0x10`. So a 12-byte flag becomes a 32-byte ciphertext (one block of plaintext + one block of padding). Don't be confused by an output that's 16 bytes "longer than expected".
6. **`x = ~(x ^ k)` is self-inverse.** Reapplying the same operation un-does it. Useful for the obfuscator, useful for me.

## 8. Cipher-fingerprint cheatsheet

| Algorithm | Fingerprint |
|---|---|
| AES | 256-byte SBox + 4×1KB T-tables fanned into XOR; round count ∈ {10, 12, 14}; key bytes packed big-endian into round keys |
| DES | IP/FP permutation tables (64-entry bit maps); 16 rounds; 8-byte block |
| RC4 | 256-byte state array; KSA loop with `S[i]/S[j]` swap; PRNG loop with same swap, `out = S[(S[i]+S[j])&0xff]` |
| TEA / XTEA | `0x9E3779B9` (delta constant); 32 rounds |
| Base64 | `>>2`, `<<4`, `& 0x3F` triple shift + 64-entry alphabet table |

| Block-cipher mode | Fingerprint |
|---|---|
| ECB | Each block independently; no chaining |
| CBC | XOR with previous ciphertext before encrypt (first block uses IV) |
| CTR | Encrypt a counter, XOR with plaintext; plaintext doesn't need padding |
| CFB / OFB | Encrypt previous ciphertext / IV stream; XOR with plaintext |

## 9. Anti-debug + self-decrypting section: standard recipe

```
RWX section + DebugBreak()/INT3 + __except_handler4
                    ↓
        SEH scope table filter checks ExceptionCode == 0x80000003
                    ↓
        target branch does IsDebuggerPresent / CheckRemoteDebuggerPresent
                    ↓
        no debugger → call decrypt(section, key, len) → call into now-decrypted code
```

**How to actually debug this without losing an evening:**

1. **Don't single-step blindly**: the debugger eats the INT3 from `DebugBreak`. Either configure it to pass exceptions on, or skip the function entirely and emulate it manually.
2. **Read the SEH scope table statically**. The table struct is `__except_handler4`'s standard format; IDA can chase the references with the right plugin or you can parse the bytes by hand.
3. **Apply the decrypt offline.** As shown above — read the section bytes, run the same transform in Python, write back into the IDB or a separate `.bin`.
4. **Patch the IDB** with the decrypted bytes and re-run the disassembler over them, or use capstone to read them inline.

## 10. End-of-pipeline obfuscation

When you see Base64 output that "should be Base64 but contains weird chars", the candidates are:

1. **Modified alphabet** — find a write to the alphabet table to confirm.
2. **Post-processing on the encoded output** — byte add/sub, reverse, XOR mask, character substitution.
3. **Nested encoding** — `Base64(XOR(Base64(...)))` or similar.

Walk xrefs to the alphabet table to rule out (1); if no writes, it's (2) or (3) and you should look for code between the Base64 output and the comparison.

## 11. Reverse-engineering principle

> Always work backwards from the final ciphertext, peeling one layer at a time. Don't try to guess the flag forwards.

```
[final ciphertext]
   │ ← undo last obfuscation
[intermediate 1]
   │ ← undo Base64
[raw AES ciphertext]
   │ ← AES decrypt
[padded plaintext]
   │ ← strip PKCS#7
[flag]
```

## 12. Tools

- IDA Pro 9.3 + IDA MCP (used `py_eval` extensively for inline transforms and capstone disassembly)
- Python (`pefile`, `capstone`, `pycryptodome`)
