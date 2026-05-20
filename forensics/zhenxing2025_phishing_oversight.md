---
type: source
created: 2026-05-19
updated: 2026-05-19
related: [[sources/zhenxing2025_phishing_oversight]]
---

# 2025 Zhenxing Cup — Phishing Oversight (English)

EML forensics. Surface: a self-sent QQ-mail phishing notice titled "关于病毒查杀的通知" (notice about virus scanning). Trap: a base64 string `Y3RmX2lzX2dvb2RfYm95` in the body decodes to `ctf_is_good_boy` — **a decoy, not the flag**. The real flag sits inside an XOR-encrypted "工具使用文档.docx" attached in the zip, and **the XOR key is exactly the decoy string**.

Concepts used: [[concepts/xor-keyed-by-decoy-string]], [[concepts/eml-attachment-extraction]]

## Header tells

```
X-Originating-IP: 127.0.0.1   ← suspicious; legit mail never shows 127.0.0.1
From: 123456789@qq.com         ← identical to To (self-spoofed)
To:   123456789@qq.com
Subject: 关于病毒查杀的通知    (gb18030 base64 decoded)
X-HAS-ATTACH: no               ← lies — there IS an attachment
Date: 2025-11-07 17:11:14 +0800
```

`X-HAS-ATTACH: no` is plain text and trivially forged. MIME structure is in fact `multipart/mixed`, with part[4] = `application/octet-stream`, filename `查杀工具.zip` (73 KB).

## Decoy in the body

Decoded body (gb18030 base64):

> This is an important notice ... please download the dedicated scanner ... **Y3RmX2lzX2dvb2RfYm95**

Base64 → `ctf_is_good_boy`.

A novice submits `flag{ctf_is_good_boy}` — **wrong**. It is the XOR key.

## Attachment chain

`查杀工具.zip` extracts to:
```
查杀工具/内部查杀工具.exe       PE32 (i386, console)
查杀工具/工具使用文档.docx      ← looks like docx, file(1) reports "data"
```

Header of `工具使用文档.docx`:
```
33 3F 65 5B 63 73 5F 67 6F 6F ...   ← not PK\x03\x04
```

A real docx (= zip) must start with `PK\x03\x04`. XOR the first 4 bytes:
```
PK\x03\x04   =  50 4B 03 04
ciphertext   =  33 3F 65 5B
xor key      =  63 74 66 5F   ← "ctf_"
```

Extending bytes 5-15 yields key `ctf_is_good_boy` — the same decoy from the email body.

## Decrypt

```python
data = open('工具使用文档.docx','rb').read()
key  = b'ctf_is_good_boy'
dec  = bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])
open('real.docx','wb').write(dec)
# real.docx now starts with 50 4B 03 04 ✓
```

`unzip` real.docx and read `word/document.xml`:

> Hello Boy: **flag{ctf_eq23-c876-dhad-2871-dkdk-lopk}**

## Answer

`flag{ctf_eq23-c876-dhad-2871-dkdk-lopk}`

## Pitfalls

- **Trust no header.** EML is plain text; `X-HAS-ATTACH: no` is a one-line forgery. Always walk MIME parts.
- **`X-Originating-IP: 127.0.0.1`** can also be forged but is the strongest red flag (no real client lives on 127.0.0.1).
- **Don't submit body-text base64 verbatim** as the flag. CTF authors love this trap. Always ask "could this string be a key / seed / path / variable name instead?"
- **`file(1)` reporting "data" instead of the expected type** almost always means XOR/single-byte encryption. When extension says docx/zip but magic bytes mismatch, try XOR with a single byte first, then a short string from somewhere nearby.

Chinese version: [[sources/zhenxing2025_phishing_oversight]]
