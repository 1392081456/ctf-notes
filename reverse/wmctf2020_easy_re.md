# WMCTF 2020 — easy_re: Unpacking a PerlApp Binary

> **Flag**: `WMCTF{I_WAnt_dynam1c_F1ag}`
>
> **Pipeline**: PerlApp wrapper EXE → BFS resource (DWORD-XOR encrypted) → directory (filenames XOR'd with `0xEA`) → individual files (optional zlib + optional XOR `0xEA`) → flag literal in `perl.pl`.

## 0. File overview

| Field | Value |
|---|---|
| File | `perl.exe` |
| Size | 1,283,584 bytes (~1.28 MB) |
| Format | PE32+ executable (console) x86-64, for MS Windows |
| Image base | `0x140000000` |
| Entry point | `0x403760` (the standard `start` thunk) |
| Sections | `.text`, `.idata`, `.rdata`, `.data`, `.pdata`, `.rsrc` |
| Functions | 156 |
| Strings | 386 |

Loading the binary into IDA the first thing that jumped out from the strings list was the PDB reference `paperl516.pdb`. That's the name ActiveState uses for the PerlApp runtime — so the binary is a PerlApp wrapper around a Perl 5.16 interpreter, and the actual challenge code is going to be a Perl script tucked away somewhere in the PE.

## 1. PerlApp in one paragraph

PerlApp packages a Perl interpreter (`perl516.dll`) plus some number of script files (and supporting `.pm` modules) into a single self-contained EXE. At runtime the wrapper:

1. locates an embedded **BFS** (Binary File System) blob that lives in `.rsrc`,
2. decrypts the BFS header and directory,
3. walks the directory to find the entry-point script (typically named `perl.pl` and pointed to by a metadata pseudo-entry called `*SCRIPTNAME`),
4. extracts that script into memory (decompressing it with zlib if needed),
5. calls into `perl516.dll` to interpret it.

So the entire challenge reduces to recovering the embedded Perl source. There is no "real" reverse engineering of the wrapper logic — only of the BFS container format.

## 2. Locating the BFS

PerlApp finds the BFS via `FindResourceA(hModule, "#1", "BFS")`. The corresponding code in `sub_406BF0`:

```c
hRsrc   = FindResourceA(hModule, "#1", "BFS");
hGlobal = LoadResource(hModule, hRsrc);
pBFS    = LockResource(hGlobal);
size    = SizeofResource(hModule, hRsrc);
```

IDA hadn't loaded `.rsrc` into the database by default, so I had to read the raw PE structure to find it. The relevant section header:

```
.rsrc:  VirtAddr=0x1B000   VirtualSize=0x121138
        FileOffset=0x18400 RawSize=0x121200
```

So the resource section is roughly 1.18 MB of the binary. Walking the resource directory tree manually:

```
Type "BFS" → Name #1 → Lang neutral → DataEntry @ RVA 0x1B138
                                    → file offset 0x18538
                                    → size 0x12121C
```

`0x18538` is where the encrypted BFS blob starts inside the file.

## 3. BFS decryption

The decryption routine is `sub_406AE0`. Its decompiled body, paraphrased:

```c
v3 = *(uint32_t*)(pBFS + 4);            // version field
if (v3 == 0x02000000)                    // big-endian sentinel
    byteswap_header_fields(pBFS);

xor_key  = *(uint32_t*)(pBFS + 8);       // also doubles as "total size"
data_off = *(uint16_t*)(pBFS + 12);      // start of encrypted region

size_t enc_size = xor_key - data_off;
for (size_t i = 0; i < enc_size; i += 4) {
    uint32_t enc = *(uint32_t*)(pBFS + data_off + i);
    *(uint32_t*)(out + i) = xor_key ^ enc;
}
```

Two subtle points:

- The same DWORD at offset 8 is **both** the XOR key and the total length of the BFS blob. That's a slightly cute trick — picking the value of one of your fields to also serve as a key.
- The encrypted region is XOR'd with the key DWORD-by-DWORD starting at the offset stored in the 16-bit field at offset 12.

Reading the actual header bytes from the file:

```
file 0x18538:  7f 3a 5b aa     # magic 0xAA5B3A7F
file 0x1853c:  02 00 00 00     # version = 2 (LE; not byteswapped)
file 0x18540:  18 0a 12 00     # XOR key = 0x00120A18
file 0x18544:  54 00           # data_offset = 84 (0x54)
```

So:

- XOR key = `0x00120A18`
- Encrypted region starts at offset 84 from the BFS base
- Encrypted region length = `0x00120A18 - 84 = 0x001209C4`
- DWORD-wise XOR

The decrypted BFS header (now starting at offset 0 of the result):

```
00:  ff 42 46 53     # signature: '\xff' 'B' 'F' 'S'   ← sanity check
04:  02 00 00 00     # version
08:  c4 09 12 00     # total size = 0x001209C4
0c:  1f 00 00 00     # entry count = 31
10:  06 00 00 00     # flags = 6 (bit1 = filenames XOR'd, bit2 = hash mode)
14:  20 00           # record size hint = 32
16:  03 00           # alignment = 3
18:  c4 02 00 00     # hash table offset = 0x2C4
1c:  1f 00 00 00     # hash table mask = 0x1F (32 slots)
```

Signature `\xffBFS` is the canonical BFS marker — confirms the decrypt key was correct.

```python
import struct

with open("perl.exe", "rb") as f:
    data = f.read()

bfs_start = 0x18538
xor_key   = struct.unpack_from("<I", data, bfs_start + 8)[0]    # 0x00120A18
data_off  = struct.unpack_from("<H", data, bfs_start + 12)[0]   # 84

enc = data[bfs_start + data_off : bfs_start + xor_key]
dec = bytearray()
for i in range(0, len(enc), 4):
    dword = struct.unpack_from("<I", enc, i)[0]
    dec += struct.pack("<I", dword ^ xor_key)

assert dec[:4] == b"\xffBFS"
```

## 4. Directory layout

Each directory record:

```
+0:  uint16  name_length
+2:  bytes   name[name_length]      # XOR-encrypted with 0xEA
     bytes   pad to alignment       # see below
+N:  uint32  data_offset            # offset within the (decrypted) BFS blob
```

Filename XOR: every byte is XOR'd with `0xEA`. Confirmation comes from `sub_406FB0`, which compares a stored name against an external string by XOR'ing each stored byte with `0xEA` on the fly:

```c
if ((flags & 2) != 0) {
    while (a3--) {
        if ((*v6 ^ 0xEA) != *a2) break;
        v6++; a2++;
    }
}
```

The padding between `name` and `data_offset` follows this rule, reverse-engineered from `sub_407290`:

```c
v25 = name_length + 2;
v22 = bfs_alignment;            // = 3 for this binary
if (v22 & v25)
    v25 = (v25 + v22 + 1) & ~v22;
// data_offset is at record_offset + v25
```

In other words, the field offset is rounded up to `(alignment+1)`-byte boundaries when needed. With `alignment = 3` that's a 4-byte alignment — straightforward.

## 5. Walking the directory

After parsing all 31 entries, the directory looks like this (decoded names; offsets are within the decrypted blob):

| Rec offset | Name |
|---|---|
| 0x0020 | `Carp.pm` |
| 0x0030 | `Exporter.pm` |
| 0x0044 | `auto/Tie/Hash/NamedCapture/NamedCapture.dll` |
| 0x0078 | `XSLoader.pm` |
| **0x008C** | **`perl.pl`** ← main script |
| 0x009C | `Errno.pm` |
| 0x00AC | `auto/PerlIO/scalar/scalar.dll` |
| 0x00D0 | `*DLMAP` |
| 0x00DC | `DynaLoader.pm` |
| 0x00F0 | `Tie/Hash/NamedCapture.pm` |
| 0x0110 | `Exporter/Heavy.pm` |
| 0x0128 | `auto/attributes/attributes.dll` |
| 0x014C | `File/Glob.pm` |
| **0x0160** | **`*SCRIPTNAME`** |
| 0x0174 | `PerlIO/scalar.pm` |
| 0x018C | `perl516.dll` |
| 0x01A0 | `strict.pm` |
| **0x01B0** | **`*SETUP`** |
| 0x01BC | `vars.pm` |
| 0x01CC | `Config.pm` |
| 0x01DC | `warnings/register.pm` |
| 0x01F8 | `warnings.pm` |
| 0x020C | `PerlIO.pm` |
| 0x021C | `Config_git.pl` |
| 0x0230 | `auto/File/Glob/Glob.dll` |
| 0x0250 | `Config_heavy.pl` |
| 0x0268 | `AutoLoader.pm` |
| **0x027C** | **`*PERLVERSION`** |
| 0x0290 | `perl.md5` |
| 0x02A0 | `attributes.pm` |
| 0x02B4 | `feature.pm` |

The names starting with `*` (`*DLMAP`, `*SCRIPTNAME`, `*SETUP`, `*PERLVERSION`) are PerlApp metadata pseudo-entries, not real files. The interesting one is `perl.pl`.

The record at 0x008C in raw bytes:

```
0x008C:  07 00                    # name_length = 7
0x008E:  9a 8f 98 86 c4 9a 86     # name (XOR 0xEA → "perl.pl")
0x0095:  23 23 23                 # padding to 4-byte alignment
0x0098:  a4 2a 00 00              # data_offset = 0x00002AA4
```

So the file body lives at offset `0x2AA4` of the decrypted blob.

## 6. File data block format

From `sub_406D40`:

```
+0:  uint32  uncompressed_size
+4:  uint32  compressed_size
+8:  uint32  flags                  # bit0 = zlib, bit1 = XOR 0xEA
+12: bytes   data[compressed_size]
```

Decompression / decryption logic:

```c
if (flags & 1)
    inflate(data, comp_size, output, &uncomp_size);     // zlib 1.2.8
else
    memcpy(output, data, uncomp_size);

if (flags & 2)
    for (i = 0; i < uncomp_size; i++)
        output[i] ^= 0xEA;
```

`perl.pl`'s data block at 0x2AA4:

```
0x2AA4:  b4 00 00 00     # uncompressed = 180
0x2AA8:  b4 00 00 00     # compressed   = 180   (so no zlib)
0x2AAC:  02 00 00 00     # flags = 2 (no zlib, XOR 0xEA only)
0x2AB0:  ... 180 bytes XOR'd with 0xEA ...
```

## 7. Putting it together

```python
import struct, zlib

with open("perl.exe", "rb") as f:
    raw = f.read()

bfs_start = 0x18538
xor_key   = struct.unpack_from("<I", raw, bfs_start + 8)[0]
data_off  = struct.unpack_from("<H", raw, bfs_start + 12)[0]

# DWORD-wise XOR decrypt of the BFS blob
enc = raw[bfs_start + data_off : bfs_start + xor_key]
dec = bytearray()
for i in range(0, len(enc), 4):
    dword = struct.unpack_from("<I", enc, i)[0]
    dec += struct.pack("<I", dword ^ xor_key)
assert dec[:4] == b"\xffBFS"

bfs_alignment = struct.unpack_from("<H", dec, 0x16)[0]   # = 3

def xor_ea(b):
    return bytes(x ^ 0xEA for x in b)

def extract(rec_off):
    nlen = struct.unpack_from("<H", dec, rec_off)[0]
    name = xor_ea(bytes(dec[rec_off + 2 : rec_off + 2 + nlen])).decode("ascii")

    v25 = nlen + 2
    if bfs_alignment & v25:
        v25 = (v25 + bfs_alignment + 1) & ~bfs_alignment
    data_offset = struct.unpack_from("<I", dec, rec_off + v25)[0]

    ucomp, comp, flags = struct.unpack_from("<III", dec, data_offset)
    body = bytes(dec[data_offset + 12 : data_offset + 12 + comp])
    if flags & 1:
        body = zlib.decompress(body)
    if flags & 2:
        body = xor_ea(body)
    return name, body

name, body = extract(0x008C)
print(name)
print(body.decode("utf-8"))
```

Output:

```perl
$flag = "WMCTF{I_WAnt_dynam1c_F1ag}";
print "please input the flag:";
$line = <STDIN>;
chomp($line);
if ($line eq $flag) {
    print "congratulation!"
} else {
    print "no,wrong"
}
```

The flag is just sitting there as a string literal: **`WMCTF{I_WAnt_dynam1c_F1ag}`**.

## 8. What I learned

1. **Recognising packers from PDB strings.** The `paperl` substring in the PDB path made the rest of the analysis a known quantity. PerlApp's BFS format has been documented before — once you have the packer's name, the rest is following the existing format docs (or, as I did, reverse-engineering the loader). Check `Strings` window for any `*.pdb` paths early; they're the cheapest possible identifier.
2. **Two layers of XOR with different scopes.** The first time I parsed the directory and got nonsense filenames I was sure my main XOR key was wrong. It wasn't — the dword XOR was right, but filenames have a *separate* per-byte XOR with `0xEA`. When one decryption layer produces partial sense (the structure parses, but some fields look like garbage), suspect a second narrower layer rather than re-deriving the first key.
3. **`.rsrc` not loaded by default.** IDA didn't pull the resource section into the database for me. I had to either add it manually with "Load additional binary file…" or read the raw PE outside of IDA. Either works; both took me about 10 minutes of confusion the first time.
4. **The "key is also the size" trick.** Cute and a little annoying — I almost interpreted offset 8 as just "size" and missed that the same DWORD is also the XOR key. The decrypt routine in `sub_406AE0` makes it obvious once you read it, but the file header alone could be misread.

## 9. Generalisation

PerlApp is one of several Perl-to-EXE packers; **Perl2EXE** and **PAR::Packer** behave similarly but use different containers and different XOR/compression conventions. The fingerprint is always the same shape: `FindResource*` with a custom resource type name, a small loader, an opaque blob in `.rsrc`. Knowing the packer's name is a huge shortcut, because someone has almost certainly reverse-engineered the container format and posted it.

The same general approach applies to other languages with EXE wrappers: PyInstaller (Python), srlua (Lua), FreeWrap (Tcl), and so on. Runtime is the EXE, the script is in resources or the overlay, encryption is usually shallow.

## 10. Tools

- IDA Pro 9.3 — static analysis, decompilation
- IDA MCP — Python interop, used to dump bytes from the database directly
- Python (`struct`, `zlib`) for the offline extractor
