---
type: source
created: 2026-05-19
updated: 2026-05-19
related: [[sources/zhenxing2025_ics_c2]]
---

# 2025 Zhenxing Cup — ICS C2 (English)

ICS traffic analysis. A 1.3 MB / 353-second pcap, 100% **OPC UA** (TCP/4840). The attacker abuses industrial data nodes as a bidirectional C2 channel: **the server writes `REACTOR-001-SEG##-<base64>` commands to Node 9, and the client writes `RESULT-SEG##-<base64>` answers back to Node 10**. Each command and each output is split into base64 chunks; reassembled it is JSON.

Concepts used: [[concepts/opcua-node-c2-channel]], [[concepts/segmented-base64-reassembly]]

## Capture overview

```
192.168.186.144 (client)  ↔  192.168.186.1:4840 (OPC UA server)
                              ↑ 8126 packets, 6600 OPC UA frames
```

OPC UA service-ID frequency (`tshark -Y opcua -T fields -e opcua.servicenodeid.numeric | sort | uniq -c`):

| Count | Service ID | Meaning |
|---|---|---|
| 3200 / 3200 | 631 / 634 | Read / ReadResponse — **server writes commands into Node 9, client polls** |
| 64 / 64 | 673 / 676 | Write / WriteResponse — **client writes command output into Node 10** |
| 28 / 28 | 554 / 557 | CreateSubscription |
| 2 / 2 | 461 / 464 | CreateSession |
| 2 / 2 | 446 / 449 | OpenSecureChannel |

## Protocol reconstruction

Server-to-client commands (carried inside ReadResponse):

```
REACTOR-001-SEG01-eyJpZCI6ICI0MTVhMT
REACTOR-001-SEG02-M1ZSIsICJjbWQiOiAi
...
REACTOR-001-SEG06-k4NDU2In0=
```

Concatenated in `SEG##` order, base64-decoded, JSON:

```json
{"id":"415a135e","cmd":"ls","timestamp":"2025-11-09T17:37:54.598456"}
```

Client-to-server responses (in WriteRequest):

```
RESULT-11-415a                ← session header (11 = total segments, 415a = id prefix)
RESULT-SEG01-eyJpZCI6ICI0MTVhMT
RESULT-SEG02-M1ZSIsICJjbWQiOiAi
...
RESULT-SEG11-OC4yNDUwMjIifQ==
```

## Full command chain

In timestamp order:

| # | Time (UTC) | Command | Output |
|---|---|---|---|
| 1 | 17:37:58 | `ls` | `flag\nopcua_client.py\n` |
| 2 | 17:38:33 | `cat flag` | **`flag{try_try_4_new_c2_0PC}`** ★ |
| 3 | 17:39:44 | `sed -i 's/t/T/g' flag` | (empty) |
| 4 | 17:40:56 | `sed -i 's/4/A/g' flag` | (empty) |

Step 2 leaks the original flag. Steps 3-4 mutate the file in place (anti-forensics or pure trap).

## Reassembly script

```python
import re, base64, json

# 1. Dump every Write's String value
#    tshark -r ics_c2.pcap -Y 'opcua.servicenodeid.numeric == 673' -V > writes.txt
data = open('writes.txt').read()
blocks = data.split('WriteValue')[1:]
results = []
for b in blocks:
    m_val = re.search(r'String: (.*)', b)
    if m_val:
        v = m_val.group(1).strip()
        if v != '[OpcUa Null String]':
            results.append(v)

# 2. Split into sessions, reorder SEGs
res_pat = re.compile(r'^RESULT-(\d+)-([0-9a-f]+)$')
seg_pat = re.compile(r'^RESULT-SEG(\d+)-(.*)$')
sessions, current = [], {}
for v in results:
    if res_pat.match(v):
        if current: sessions.append(current)
        current = {}
        continue
    m = seg_pat.match(v)
    if m: current[int(m.group(1))] = m.group(2)
if current: sessions.append(current)

# 3. Decode each session
for segs in sessions:
    b64 = ''.join(segs[k] for k in sorted(segs))
    obj = json.loads(base64.b64decode(b64))
    print(obj['cmd'], '->', obj['output'][:80])
```

## Answer

`flag{try_try_4_new_c2_0PC}` (the original content read by `cat flag`).

> Fallback: `flag{Try_Try_A_new_c2_0PC}` if the checker wants the file state after both seds.

## Pitfalls

- **OPC UA is not encrypted by default.** With `SecurityPolicy=None` and `MessageSecurityMode=None`, every node write is plaintext-visible. The attacker leverages the fact that no DPI engine inspects field-level payload semantics in industrial protocols.
- **String-node writes as a C2 channel** is a new ICS-attack pattern; classic IDS does not match base64 inside OPC UA String fields. Tells: base64 in String fields, segment markers (SEG/CHUNK/PART), and write frequency far above what a normal status node should produce.
- **`tshark -V` output contains date strings like `Nov  9, 2025 04:35:45.386551000 EST`** whose leading zeros choke `python3 -c "..."` heredocs (`SyntaxError: leading zeros`). Either redirect to a file first, or use a `<< 'PY'` quoted heredoc.
- **The OPC UA service ID field is `opcua.servicenodeid.numeric` in tshark**, not `opcua.service`.
- **sed-on-the-flag at the end** is a common CTF feint: the in-file final state differs from what the attacker actually exfiltrated. Submit whichever the checker wants; usually it is the value the attacker read via `cat`.

Chinese version: [[sources/zhenxing2025_ics_c2]]
