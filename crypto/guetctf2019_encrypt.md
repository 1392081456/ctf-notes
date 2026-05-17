# GUET-CTF 2019 — encrypt: RC4 plus a Shifted Base64 Alphabet

> **Flag**: `flag{e10adc3949ba59abbe56e057f20f883e}` (yes, that's `MD5("123456")` — small Easter egg)
>
> **Pipeline**: `input → RC4 (key = [16,32,48,48,32,32,16,64], 8 bytes) → custom Base64 (alphabet shifted by +61) → compared to a 52-byte constant in .data`.

## 0. File overview

| Field | Value |
|---|---|
| File | `encrypt 3` (note the space in the name) |
| Format | ELF 64-bit LSB executable, x86-64, dynamically linked |
| Functions | 30 |
| Strings | 15 |
| Imports | `printf`, `scanf`, `strlen`, `memset`, `puts` |
| Notable strings | `"please input your flag:"`, `"Wrong"`, `"Good"` |

Linux ELF, not a Windows PE — small but the surface area for tricks is similar.

## 1. main

Decompiled `main`:

```c
__int64 main(void) {
    char v10[8] = {16, 32, 48, 48, 32, 32, 16, 64};   // RC4 key (8 bytes)
    char s[256];                                        // input buffer
    char v12[1032];                                     // output (Base64-encoded)
    char v9[1040];                                      // RC4 state object
    int  v4 = 0;                                        // out_len receiver

    memset(s, 0, 256);
    printf("please input your flag:");
    scanf("%s", s);

    sub_4006B6(v9, v10, 8);                  // RC4 KSA
    sub_4007DB(v9, s, strlen(s));            // RC4 PRNG (in-place XOR)
    sub_4008FA(s, strlen(s), v12, &v4);      // custom Base64

    for (int i = 0; i <= 50; i++) {
        if (v12[i] != byte_602080[i]) {
            puts("Wrong");
            return 0;
        }
    }
    puts("Good");
    return 0;
}
```

So:

```
input → RC4 → custom Base64 → compare against byte_602080[0..50]
```

51 bytes of comparison; the constant `byte_602080` is in `.data`. RC4 is a stream cipher, so it doesn't change length: input length and post-RC4 length are equal. After Base64 the length grows by a 4/3 factor; if the Base64 output is 51 bytes (with one trailing `=`), the original input length is `(51 - 1) * 3 / 4 + ...` → 38 bytes. That happens to be the exact length of `flag{e10adc3949ba59abbe56e057f20f883e}` (38 chars). Comforting.

## 2. RC4 — KSA (`sub_4006B6`)

```c
void sub_4006B6(int *state, uint8_t *key, int key_len) {
    int S[256];

    // S-box init
    for (int i = 0; i < 256; i++)
        S[i] = i;

    // Key schedule
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[j % key_len]) & 0xFF;
        swap(S[i], S[j]);
    }

    // Save state for the PRNG
    state[0] = i;                    // = 256 at loop end (stored as int — quirky but harmless)
    state[1] = j;                    // final j
    memcpy(state + 2, S, 256 * sizeof(int));
}
```

The 256-iteration loop with two-pointer swap and modular addition is the unmistakable RC4 KSA fingerprint. This implementation is almost textbook except it stores `i` and `j` as 32-bit ints in the state object (so the PRNG can resume) — and it indexes the key with `j % key_len` rather than the more common `i % key_len`. That second detail bit me; see § 8.

## 3. RC4 — PRNG (`sub_4007DB`)

```c
void sub_4007DB(int *state, uint8_t *data, int len) {
    int i  = state[0];
    int j  = state[1];
    int *S = state + 2;

    for (int k = 0; k < len; k++) {
        i = (i + 1) & 0xFF;
        j = (j + S[i]) & 0xFF;
        swap(S[i], S[j]);
        data[k] ^= S[(S[i] + S[j]) & 0xFF];
    }

    state[0] = i;
    state[1] = j;
}
```

Plain RC4 PRNG — for each byte, advance `i`, advance `j` by `S[i]`, swap, XOR data with `S[(S[i] + S[j]) & 0xFF]`.

## 4. The key

```c
char rc4_key[8] = {16, 32, 48, 48, 32, 32, 16, 64};
// hex:    {0x10, 0x20, 0x30, 0x30, 0x20, 0x20, 0x10, 0x40}
// ASCII:  {DLE,  SP,   '0',  '0',  SP,   SP,   DLE,  '@'}
```

The bytes look like garbage; not a printable ASCII key. Doesn't matter — we just need the byte values.

## 5. Custom Base64 (`sub_4008FA`)

Decompiled (shortened):

```c
void sub_4008FA(char *input, int len, char *output, int *out_len) {
    int v15 = 0;                                  // output cursor

    for (int v16 = 0; v16 < len; ) {
        uint8_t v12 = input[v16++];
        uint8_t v13 = (v16 < len) ? input[v16++] : 0;
        uint8_t v14 = (v16 < len) ? input[v16++] : 0;

        // Standard Base64 6-bit packing, but +61 instead of an alphabet table lookup
        output[v15    ] = ((v12 >> 2) & 0x3F)                          + 61;
        output[v15 + 1] = (((v13 >> 4) | (16 * v12)) & 0x3F)           + 61;
        output[v15 + 2] = (((v14 >> 6) | (4  * v13)) & 0x3F)           + 61;
        output[v15 + 3] =  (v14 & 0x3F)                                + 61;
        v15 += 4;
    }

    // Padding: replace tail bytes with '=' (== 61)
    if (len % 3 == 1) {
        output[--v15]   = 61;
        output[v15 - 1] = 61;
    } else if (len % 3 == 2) {
        output[v15 - 1] = 61;
    }
    *out_len = v15;
}
```

Two important features:

1. **No alphabet table.** Standard Base64 looks up the 6-bit index in a 64-byte table like `"ABCDEFGHIJ...+/"`. This implementation just **adds 61 to the index**, which equals `chr(0x3D + idx)`. So:
   - Index 0 → `=` (0x3D)
   - Index 1 → `>` (0x3E)
   - Index 2 → `?` (0x3F)
   - …
   - Index 63 → `|` (0x7C)
2. **Padding character is the same as index 0.** Both are `=` (0x3D). So the encoded output's trailing `=`s could in principle be ambiguous, but real Base64 padding only legally appears at the end and only in 0/1/2 trailing chars — not a problem in practice.

Comparing to standard Base64:

```
Standard:  A-Z (0..25), a-z (26..51), 0-9 (52..61), '+' (62), '/' (63)
Custom:    indices 0..63 → ASCII 61..124 → "= > ? @ A B ... y z { | "
```

## 6. The expected ciphertext

`byte_602080` in `.data`, 52 bytes total:

```
Offset  Bytes
00-0F   5a 60 54 7a 7a 54 72 44  7c 66 51 50 5b 5f 56 56
10-1F   4c 7c 79 6e 65 55 52 79  55 6d 46 6b 6c 56 4a 67
20-2F   4c 61 73 4a 72 6f 5a 70  48 52 78 49 55 6c 48 5c
30-33   76 5a 45 3d
```

Last byte `0x3D` is `'='`, second-to-last `0x45` is `'E'` (a real char, not padding) → exactly **one trailing `=`** → the original RC4 output length was 38 bytes (51 actual chars + 1 `=`).

## 7. Solution

```python
expected = bytes([
    0x5a, 0x60, 0x54, 0x7a, 0x7a, 0x54, 0x72, 0x44,
    0x7c, 0x66, 0x51, 0x50, 0x5b, 0x5f, 0x56, 0x56,
    0x4c, 0x7c, 0x79, 0x6e, 0x65, 0x55, 0x52, 0x79,
    0x55, 0x6d, 0x46, 0x6b, 0x6c, 0x56, 0x4a, 0x67,
    0x4c, 0x61, 0x73, 0x4a, 0x72, 0x6f, 0x5a, 0x70,
    0x48, 0x52, 0x78, 0x49, 0x55, 0x6c, 0x48, 0x5c,
    0x76, 0x5a, 0x45, 0x3d,
])

# Step 1: invert the +61 shift
sixbit = [b - 61 for b in expected]

# Step 2: pack 6-bit indices back into 8-bit bytes
decoded = bytearray()
for i in range(0, len(sixbit), 4):
    c0, c1, c2, c3 = sixbit[i], sixbit[i+1], sixbit[i+2], sixbit[i+3]
    decoded.append((c0 << 2) | (c1 >> 4))
    if c2 == 0 and c3 == 0:                 # two-`=` padding
        break
    decoded.append(((c1 & 0xF) << 4) | (c2 >> 2))
    if c3 == 0:                              # one-`=` padding
        break
    decoded.append(((c2 & 3) << 6) | c3)

# Step 3: RC4 — KSA
key = [16, 32, 48, 48, 32, 32, 16, 64]
S = list(range(256))
j = 0
for i in range(256):
    j = (j + S[i] + key[i % len(key)]) & 0xFF
    S[i], S[j] = S[j], S[i]

# Step 4: RC4 — PRNG (RC4 is symmetric: encrypt twice with same key returns plaintext)
i = j = 0
flag = bytearray()
for byte in decoded:
    i = (i + 1) & 0xFF
    j = (j + S[i]) & 0xFF
    S[i], S[j] = S[j], S[i]
    k = S[(S[i] + S[j]) & 0xFF]
    flag.append(byte ^ k)

print(flag.decode("ascii"))
```

Output:

```
flag{e10adc3949ba59abbe56e057f20f883e}
```

`e10adc3949ba59abbe56e057f20f883e` is the MD5 of `123456`, the most common bad password in the wild — a small Easter egg from the challenge author.

## 8. The KSA index quirk

The decompiled KSA used `key[j % key_len]` whereas textbook RC4 uses `key[i % key_len]`. I tried a literal-translation Python first that mirrored the binary's `j %` form, and it produced the wrong S-box. Swapping to `i %` (textbook) gave the right flag.

There are two ways this could be:

- **Hex-Rays decompiler artefact.** Hex-Rays sometimes mis-names the loop variable when both `i` and `j` are in registers and one is dead. The actual machine code probably indexes by `i`. This is the more likely explanation.
- **The author wrote it with `j` and used the same form on both ends.** If both encrypt and decrypt use the `j %` variant, they'll round-trip with each other even though they don't match a third party's textbook RC4.

Practical takeaway: when an RC4 decompilation looks "almost right" but produces the wrong bytes, try both `key[i % n]` and `key[j % n]` in the KSA. Two-second test, big payoff.

## 9. Generalisation

The 6-bit-pack and (table lookup OR arithmetic transform) pattern in IDA is very identifiable: shift-and-OR three input bytes into four 6-bit slices, then either look each slice up in a 64-byte table or apply a small math transform. Variants I've seen in CTFs:

- Standard alphabet, no changes.
- A permuted alphabet — crackable by dumping the table or with a known plaintext.
- A continuous-range shift (this challenge): alphabet is one contiguous ASCII run.
- A different padding character (e.g. `*` instead of `=`).
- "Base32" or "Base85" variants with the same shift idea.

For RC4: 256-byte S-box init + KSA loop + PRNG loop is the entire algorithm. The fingerprint is loud — there's basically no other widely-used cipher whose disassembly looks like that.

## 10. Tools

- IDA Pro 9.3 (decompilation; the small static binary doesn't need a debugger)
- Python (no third-party crypto needed — RC4 and Base64 are 30 lines)
