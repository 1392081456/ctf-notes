# OtterCTF 2018 — Name Game (Memory Forensics)

> **Flag**: `CTF{0tt3r8r33z3}`
>
> A 2 GB Windows 7 SP1 x64 memory dump, the question is "what's the victim's in-game character name". The intended path is `volatility windows.pslist → memdump → strings` — but the first step fails silently on this dump under Volatility 3, and every dump plugin that depends on `pslist` cascades into the same failure. This writeup is about the *fallback chain*: how to identify the failure, what to switch to (`psscan`), and how to extract the answer by reading WZ-format records directly out of `strings` output when the standard tooling is broken.

## 0. File overview

| Field | Value |
|---|---|
| File | `OtterCTF.vmem` |
| Size | 2 GB raw memory dump |
| MD5 | `ad51f4ada4151eab76f2dce8dea69868` |
| OS | Windows 7 SP1 x64 (NT 6.1) |
| Captured | 2018-08-04 19:34:22 UTC |
| Tool | Volatility 3 (v2.28 at time of writing) — but see §2 |

Sanity check:

```
$ vol -q -f OtterCTF.vmem windows.info
SystemTime      2018-08-04 19:34:22+00:00
Is64Bit         True
NtMajorVersion  6   NtMinorVersion  1     → Windows 7 x64 SP1
```

## 1. The standard chain (which fails)

The intended approach for "what's running on this box" is:

```
$ vol -q -f OtterCTF.vmem windows.pslist
```

Result:

```
PID    PPID   ImageFileName     Offset    ...
                                           ← empty, no rows
```

`pslist` walked the EPROCESS doubly-linked list (`PsActiveProcessHead`) and got back nothing. On this particular dump, the list pointers seem corrupted or relocated in a way Volatility 3's heuristics can't handle. Everything that builds on `pslist` — `windows.memmap`, `windows.pstree`, `--dump` for any pid — also produces nothing.

This is a real-world failure mode: not every dump plays nice with every Volatility version, and silent empty output is the worst kind of failure because nothing prints "error".

## 2. The fallback — `psscan`

`psscan` doesn't walk the process list. It scans physical memory for pool tags matching `_EPROCESS` structures. Slower, less neat, but resilient against list-linking corruption:

```
$ vol -q -f OtterCTF.vmem windows.psscan | grep -iE "lunar|game|maple"
708  2728  LunarMS.exe  0x7d7cb740  18  346  1  True  2018-08-04 19:27:39
```

`LunarMS.exe` is a MapleStory private server client — the game in question. The character name lives somewhere in this process's heap.

### Why dumping the process still fails

```
$ vol -q -f OtterCTF.vmem windows.memmap --pid 708 --dump
$ vol -q -f OtterCTF.vmem windows.pslist --pid 708 --dump
```

Both produce nothing. The `--dump` machinery for `memmap` (and most other dumpers) goes through `pslist` to resolve the PID to an EPROCESS — and `pslist` is the broken step. We have a process offset from `psscan`, but the dump plugins don't accept raw offsets.

## 3. Three paths forward

1. **Switch to Volatility 2.** The `Win7SP1x64` profile is stable on this image. Would absolutely work, but requires installing/configuring vol2 alongside vol3.
2. **Manually walk VAD from the `psscan` offset.** Possible — open the dump in a hex editor at `0x7d7cb740`, parse the EPROCESS structure, follow `VadRoot`, walk regions, dump. Lots of work.
3. **Skip plugin-based extraction entirely. Run `strings` on the whole dump and use the game's data format as an anchor.**

I went with option 3. On a 2 GB dump with a clear anchor string, `strings | grep` is faster end-to-end than wrestling with the plugin chain.

## 4. Anchor strategy

MapleStory channels are named `Lunar-1`, `Lunar-2`, `Lunar-3`, `Lunar-4`. The current channel (and the character's name, since the client keeps both in the same runtime structure) will appear adjacent in memory.

```
$ strings -n 5 OtterCTF.vmem | grep -n "Lunar-3"
3696367:Lunar-3
3718969:Lunar-3
```

Two hits, both clean. The first one's neighbourhood is what we want to read carefully.

## 5. Identifying the record format

Hexdump around the first `Lunar-3`:

```
1d 00 00 00   01 00 00 00   <u32 len>   <u32 len>   <ASCII string>   <padding>
```

The two repeated `u32 length` fields are characteristic of Nexon's **WZ resource table** format — the length is stored twice as a checksum / corruption guard. Each record is 33 bytes including header + length-fields + variable payload + alignment padding.

So we have a structured record layout we can parse, rather than guessing which adjacent string is "the answer".

## 6. Parsing the records programmatically

```python
import mmap
import struct

with open("OtterCTF.vmem", "rb") as f:
    mm = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)

# 8-byte record signature: type 0x1d, version 0x01
sig = b"\x1d\x00\x00\x00\x01\x00\x00\x00"

# Window around our anchor hit
p, end = 0x44a0f000 - 0x200, 0x44a0f000 + 0x600

while p < end:
    idx = mm.find(sig, p, end)
    if idx < 0:
        break
    l1, l2 = struct.unpack("<II", mm[idx+8:idx+16])
    # the two lengths must agree, and length must be in a reasonable range
    if l1 == l2 and 1 <= l1 <= 64:
        print(hex(idx), l1, mm[idx+16 : idx+16+l1])
    p = idx + 1
```

Output:

```
0x44a0f060  7   b'Lunar-3'
0x44a0f081  11  b'0tt3r8r33z3'
0x44a0f0a2  13  b'Sound/UI.img/'
0x44a0f0c3  12  b'BtMouseClick'
0x44a0f0e4  7   b'Lunar-4'
0x44a0f105  7   b'Lunar-1'
0x44a0f126  7   b'Lunar-2'
```

`Lunar-3` is the current channel. The very next *independent* record is `0tt3r8r33z3` — that's our character name. The records after are UI sound paths and a list of available channels to switch to.

## 7. Cross-validating

A second hit on a different offset gave residual HTTP login data:

```
http://lunarms.zapto.org/username0tt3r8r33z3password
```

Same string, in a totally different context (HTTP request fragment vs. WZ resource record). The account name equals the character name equals `0tt3r8r33z3`. Two independent confirmations from the same dump.

## 8. Final answer

```
CTF{0tt3r8r33z3}
```

## 9. Traps and lessons learned

| Trap | Why it cost me time | Resolution |
|---|---|---|
| `pslist` returned no rows silently | Stared at the blank output for a while thinking I'd run it wrong | Compare against `windows.info` — that gives a non-empty result, so the dump is parseable, just not by pslist on this version. Use `psscan` |
| Cascading dump failures | `memmap --dump`, `pslist --dump` etc. all empty — same root cause, but separate plugin calls | Once `pslist` fails on a dump, **every** dump plugin built on top of it fails the same way. Don't waste time on each one individually |
| Treated `strings` neighbours as related | First instinct was "string near `Lunar-3` is the character name" | Memory pool allocators interleave unrelated data. Need to identify a record format to know what's a real adjacent record vs. a pool neighbour |
| Forgot string encoding | Some MapleStory data is UTF-16LE; spent time looking for `Lunar` in `strings -el` separately | For this dump the strings of interest were ASCII. But always run both `strings -a` (default 7-bit) and `strings -el` (UTF-16LE) on Windows dumps |
| Tried to dump the process to its own file first | "Logically" wanted process memory as a standalone file before searching | Skip — `strings` over the full dump is fine when the dump fits in disk cache. Process isolation is only needed when you have many candidate processes to disambiguate |

## 10. Methodology takeaways

1. **Always have a fallback for `pslist`.** On any forensic dump where you can't easily install another Volatility version: `psscan` (pool tag scan) is your friend. It bypasses linked-list corruption.
2. **`windows.info` is the sanity test.** If `info` works but `pslist` doesn't, the dump is fine but the plugin's heuristics broke. If `info` also fails, the dump itself is corrupt or wrong format.
3. **Strings + anchor beats full plugin pipeline on big dumps.** When you have a known string anchor (channel name, brand name, file path), `grep` is O(n) and reads cleanly. Plugin-based dumping is convoluted in comparison.
4. **Read the data format, don't guess from adjacency.** Memory is a heap and pool allocator's playground; adjacent strings are usually unrelated. A short record-format identification step pays off enormously — you go from "this might be the answer" to "this is the answer, here's the format that proves it".
5. **Cross-validate with a second independent location.** Memory dumps have redundancy — caches, log buffers, HTTP traces, autocomplete data. If you find `X` in one place, search for `X` to confirm it appears elsewhere in a different context. That's the difference between a guess and an answer.

## 11. Related techniques

- [Volatility 3 `pslist` fallback note](https://volatility3.readthedocs.io/) — official docs on plugin failure modes
- WZ file format reverse-engineering: see [HaRepacker source](https://github.com/lastbattle/Harepacker-resurrected) for the canonical Nexon resource layout
- For Windows 7 SP1 x64 dumps specifically, `vol2 --profile=Win7SP1x64` is still the most stable analyser
