# DASCTF 2025 H1 · Webshell_Plus — Writeup

> Traffic Analysis / Misc · BlueTrace.pcapng (21 MB)
> Source: https://xj.edisec.net/challenges/164

**Flag**: `DASCTF{0ba687ee-60e0-4697-8f4c-42e9b81d2dc6}`

---

## Challenge Summary

> This traffic feels both familiar and unfamiliar... the flag is the MD5 of the root user's password.

The "familiar yet unfamiliar" hint is the key: **the "webshell" concept is familiar, but the carrier is unfamiliar** — not HTTP, but **Bluetooth OBEX (Object Exchange)**.

Five nested layers:

```
Bluetooth H4 capture
  └── OBEX PUT (Bluetooth file push)
        └── yuji.jpg (19 MB JPEG)
              └── 20 KB trailer after JPEG EOI
                    └── Encrypted ZIP (password = target device name in GBK)
                          └── flag.png (100×100 grayscale)
                                └── R-channel bytes = UTF-8 text → flag
```

---

## Step 1: Identify the Protocol Stack

```bash
capinfos BlueTrace.pcapng
# Encapsulation: Bluetooth H4 with linux header
# Number of packets: 34746, capture duration 305s

tshark -r BlueTrace.pcapng -q -z io,phs | head
# frame → bluetooth → hci_h4 → bthci_acl → btl2cap → btrfcomm → obex (20 K frames)
```

**Key finding**: 99% of the payload frames are **OBEX (Bluetooth Object Exchange)**, totaling ~20 MB. A normal webshell challenge would focus on HTTP/TCP; this one swaps the carrier to a Bluetooth serial link — exactly the "unfamiliar" part of the hint.

```bash
tshark -r BlueTrace.pcapng -Y "obex.name" \
  -T fields -e frame.number -e obex.name -e obex.type -e obex.length
# 4267  yuji.jpg  image/jpeg  19657885
```

→ A single object was transferred: `yuji.jpg`, 19,657,885 bytes.

## Step 2: Reconstruct the File from OBEX

**Pitfall**: `tshark --export-objects` supports only http / imf / smb / tftp / x509af — **NOT obex**. You must reassemble it manually.

OBEX carries fragmented data in `Body (0x48)` / `End Of Body (0x49)` headers, and tshark exposes both through the field `obex.header.value.byte_sequence`:

```bash
tshark -r BlueTrace.pcapng -Y "obex" \
  -T fields -e obex.header.value.byte_sequence \
  | tr -d '\n,' | tr -d ' ' \
  | tr -dc '0-9a-fA-F' \
  > yuji_hex.txt

python3 -c "
data = bytes.fromhex(open('yuji_hex.txt').read())
open('yuji.jpg','wb').write(data)
print(data[:4].hex(), len(data))   # ffd8ffe1 19657885
"
```

`file yuji.jpg` → `JPEG image data, Exif, baseline, 8915x4540` ✓

> Note: in the first PUT frame `obex.header.value.byte_sequence` is shared by both the `Type ("image/jpeg")` header and the `Body`, but tshark only emits the last match, so the concatenated hex is pure Body without contamination.

## Step 3: JPEG Trailer

```python
data = open('yuji.jpg','rb').read()
eoi  = data.rfind(b'\xff\xd9')              # 19637710
trailer = data[eoi+2:]                       # 20173 bytes
print(trailer[:4])                           # b'PK\x03\x04' → ZIP
open('trailer.zip','wb').write(trailer)
```

```
$ unzip -l trailer.zip
    21087  2025-05-31 13:00   flag.png
        0  2025-05-31 13:01   压缩包密码是蓝牙传输的目标电脑名字.txt
```

The ZIP ships its own hint file (filename means "the ZIP password is the name of the target computer in the Bluetooth transfer").

## Step 4: Finding the Target Computer Name (encoding gotcha)

```bash
# The OBEX CONNECT packet's direction reveals src / dst
tshark -r BlueTrace.pcapng -Y "obex.opcode == 0x80" | head -2
# HonorDevice_a5:ee:96 (Infernity) → WNC_84:43:c3 (INFERNITYのPC)  Connect
```

Source: an Honor phone named `Infernity`. **Target PC: `INFERNITYのPC`** (contains the Japanese kana `の`).

Raw bytes from an EIR frame:
```
49 4e 46 45 52 4e 49 54 59  e3 81 ae  50 43
I  N  F  E  R  N  I  T  Y    の(UTF8)   P  C
```

**Using UTF-8 to encode `INFERNITYのPC` as the ZIP password fails!** ZipCrypto uses the raw password byte sequence as key material, and the author created the ZIP on Windows where the Chinese IME's default encoding is **GBK**:

| Encoding | bytes for `の` | total length |
|----------|----------------|--------------|
| UTF-8 | `e3 81 ae` | 14 B |
| **GBK** | **`a4 ce`** | **13 B** ✓ |
| Shift-JIS | `82 cc` | 13 B |

```python
import zipfile
pwd = "INFERNITYのPC".encode("gbk")          # b'INFERNITY\xa4\xcePC'
zipfile.ZipFile("trailer.zip").extractall(pwd=pwd)
```

## Step 5: Decode the flag.png Pixels

```
flag.png: PNG image data, 100 x 100, 8-bit/color RGB, non-interlaced
```

The 100×100 image looks like pure noise. `zsteg` gives the decisive hint:

```
imagedata           .. text: "&&&mmm###"
```

`&` (38), `m` (109), `#` (35) are R-channel values of consecutive pixels, and crucially **every pixel has R==G==B** (grayscale). 10000 pixels = exactly 10000 bytes.

**Take the R channel byte stream and decode as UTF-8**:

```python
from PIL import Image
img = Image.open('flag.png').convert('RGB')
raw = img.getchannel('R').tobytes()          # 10000 B
text = raw.decode('utf-8', errors='replace')
print(text)
```

The output is a 4182-character Chinese CTF-introduction article. The flag is embedded at the end of the Misc paragraph:

> 调查取证（Misc）：...尝试将隐藏的信息恢复出来即可获得 flag:**DASCTF{0ba687ee-60e0-4697-8f4c-42e9b81d2dc6}**

Strip the UUID dashes and you get the standard MD5 `0ba687ee60e046978f4c42e9b81d2dc6` (i.e. "MD5 of the root password" as stated in the prompt).

---

## Key Lessons

| Pitfall | Correct Approach |
|---------|------------------|
| `tshark --export-objects obex` does not exist | Manually concatenate the hex from `obex.header.value.byte_sequence` |
| Decoding a `の` ZIP password as UTF-8 | **ZIPs created on Windows commonly use GBK / Shift-JIS for non-ASCII passwords**; brute-force try UTF-8 / GBK / Shift-JIS / CP932 |
| Treat any 100×100 noise PNG as LSB | First check if R==G==B (grayscale) and whether the channel bytes are ASCII / UTF-8 text |
| Force the title "Webshell_Plus" to mean HTTP/TCP webshell | The "unfamiliar carrier" hint → inspect the full protocol stack; if the main payload isn't IP, change direction |

## Toolchain

- **tshark** — protocol hierarchy (`-z io,phs`), field extraction (`-T fields -e`), packet detail (`-V -Y`)
- **Python + Pillow** — grayscale pixel → byte stream
- **unzip / Python zipfile** — password-protected ZIP (encoding matters)
- **zsteg** — hints when channel bytes are ASCII rather than LSB

## File Inventory

| File | Description |
|------|-------------|
| `BlueTrace.pcapng` | Original capture |
| `solve.py` | One-shot solve script |
| `yuji.jpg` | JPEG reassembled from OBEX (with trailer) |
| `trailer.zip` | Encrypted ZIP carved from JPEG trailer |
| `flag.png` | Steganographic PNG extracted from ZIP |
| `flag_text.txt` | UTF-8 text decoded from grayscale pixels |

## References

- Challenge source: https://xj.edisec.net/challenges/164
- OBEX protocol: [IrDA Object Exchange Protocol v1.5](https://www.irda.org/standards/)
- Bluetooth packet capture: Windows 11 Wireshark + Microsoft USBPcap Bluetooth (`TCP@127.0.0.1:24352`)
