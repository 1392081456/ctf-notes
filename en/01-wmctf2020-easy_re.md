# WMCTF 2020 — easy_re: Unpacking a PerlApp Binary

## TL;DR

The challenge ships a stripped Windows PE that turns out to be a Perl script wrapped by **PerlApp**, an older Perl-to-EXE packer. The script lives in a custom PE resource called `BFS` (Binary File System), encrypted with two layered XOR transforms. Once you locate the resource, decrypt the dword-stream with the key embedded in its header, walk the directory entries (whose filenames use a separate per-byte XOR), and optionally zlib-decompress each file body, you can read the flag straight out of the original Perl source.

## First look

```
$ file easy_re.exe
easy_re.exe: PE32 executable (console) Intel 80386, for MS Windows
$ wc -c easy_re.exe
1247232 easy_re.exe
```

About 1.2 MB. Stripped. Running it just prints a banner before exiting, so the interesting code path is gated.

I opened it in IDA. `WinMain` is a thin wrapper that grabs a resource and hands it to a function I'll call `bfs_load`. The first signs that this is a packer:

```
LoadLibraryA("kernel32.dll")
FindResourceA(NULL, "#1", "BFS")
LoadResource
LockResource
SizeofResource
```

A custom resource type called `BFS` is the giveaway. Searching for known Windows packers that use exactly that resource type name pointed me at PerlApp. Confirmed by:

- the literal string `Panic: _paperl not defined` in the `.rdata` strings list,
- substrings `PerlApp::_init` and `paperl` scattered through the binary,
- a PDB-style symbol containing `paperl` in IDA's name list.

So the binary is a PerlApp wrapper. The actual Perl source must be inside the BFS blob.

## The BFS resource layout

PerlApp stores a small filesystem in `.rsrc`. The header that I cared about is just three fields:

```
offset 0x00 : magic / version (irrelevant for extraction)
offset 0x08 : 32-bit XOR key  (k)
offset 0x0C : 16-bit start offset of the directory entries
```

Once you have `k` and the directory start offset, every dword in the BFS blob from that offset to the end is XOR'd with `k`. The decrypt routine in IDA (`sub_406AE0` in my idb) is a tight loop that boils down to:

```c
for (i = start_off; i + 4 <= total_len; i += 4) {
    *(uint32_t*)(buf + i) ^= key;
}
```

After that pass you get a directory of file records. Each record is:

```
WORD  name_len
BYTE  name[name_len]
BYTE  pad to 4-byte alignment
DWORD data_offset           ; offset within the BFS blob
```

The filenames are themselves XOR'd, but with a **different** key — every byte of the name is XOR'd with `0xEA`. I missed this on the first pass and got garbage filenames. The per-byte loop in `sub_406FB0` (`*v6 ^ 0xEA`) is what gave it away.

Each entry's `data_offset` points to a small data block:

```
DWORD  uncomp_size
DWORD  comp_size
DWORD  flags
BYTE   data[comp_size]
```

`flags` has two bits I cared about:

- `flags & 1` → `data` is zlib-compressed; inflate to recover `uncomp_size` bytes.
- `flags & 2` → `data` is XOR'd byte-wise with `0xEA` (in addition to / before the inflate, depending on the order in the loader — for this binary it's applied before zlib).

## Extraction script

```python
import struct, zlib, os, pefile

def extract_bfs(exe_path, out_dir):
    pe = pefile.PE(exe_path)

    # Find the BFS resource by walking the resource directory tree.
    blob = None
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        rtype = entry.name.string if entry.name else None
        if rtype == b"BFS":
            leaf = entry.directory.entries[0].directory.entries[0].data
            rva, size = leaf.struct.OffsetToData, leaf.struct.Size
            blob = pe.get_memory_mapped_image()[rva:rva+size]
            break
    if blob is None:
        raise SystemExit("BFS resource not found")

    key       = struct.unpack_from("<I", blob, 8)[0]
    dir_start = struct.unpack_from("<H", blob, 12)[0]

    # Dword-wise XOR from dir_start to the end.
    raw = bytearray(blob)
    for i in range(dir_start, len(raw) - 3, 4):
        v = struct.unpack_from("<I", raw, i)[0] ^ key
        struct.pack_into("<I", raw, i, v)

    os.makedirs(out_dir, exist_ok=True)
    p = dir_start
    while p < len(raw):
        nlen = struct.unpack_from("<H", raw, p)[0]
        if nlen == 0 or nlen > 256:
            break
        p += 2
        name = bytes(b ^ 0xEA for b in raw[p:p+nlen]).decode("latin1")
        p += nlen
        p += (-p) & 3                                    # 4-byte align

        data_off = struct.unpack_from("<I", raw, p)[0]
        p += 4

        ucomp, comp, flags = struct.unpack_from("<III", raw, data_off)
        body = bytes(raw[data_off+12:data_off+12+comp])
        if flags & 2:
            body = bytes(b ^ 0xEA for b in body)
        if flags & 1:
            body = zlib.decompress(body)

        out_path = os.path.join(out_dir, os.path.basename(name) or f"file_{p:x}")
        with open(out_path, "wb") as f:
            f.write(body)
        print(f"  -> {name}  ({len(body)} bytes)")

if __name__ == "__main__":
    extract_bfs("easy_re.exe", "out")
```

This dumps about a dozen files into `out/`, including a `main.pl` that holds the flag-checking logic. The flag itself is plainly visible inside that script (or computed from a constant after a single `pack`/`unpack` round, depending on the iteration of the challenge).

## What tripped me up

Three things I would do differently next time:

1. **Filename XOR is separate from content XOR.** I looked at the directory after the dword XOR pass, saw what looked like junk strings, and assumed the dword key was wrong. I went back and spent an hour re-deriving the key. Looking at any byte-level loop near the directory parser would have shown me the `0xEA` immediately. Lesson: when one layer of decryption produces *partial* sense (sensible structure but unreadable strings), suspect a second, narrower layer rather than a wrong key.
2. **Padding alignment.** The records are 4-byte aligned after the variable-length name. I forgot the padding once and walked off-record into junk. `p += (-p) & 3` is the cleanest way to handle it.
3. **Resource enumeration.** I tried `pefile.PE.DIRECTORY_ENTRY_RESOURCE` and indexed into `.entries[0]` blindly at first. Walking the tree and matching the resource type as a string is more robust if the BFS isn't the only custom resource.

## Generalization

PerlApp is one of several Perl-to-EXE packers; **Perl2EXE** and **PAR::Packer** behave similarly but use different containers and different XOR/compression conventions. The fingerprint is always the same shape: `FindResourceA` (or its Unicode sibling) with a custom type name, a small loader function, and an opaque blob in `.rsrc`. Knowing the packer's name shortcuts the rest, because somebody has almost always reverse-engineered the container format and written it up.

The same general approach works for other languages with EXE wrappers — Python via PyInstaller, Lua via srlua, Tcl via FreeWrap. The runtime is the EXE; the script is somewhere in resources or the overlay; the encryption is usually shallow.
