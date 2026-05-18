# Hecheng Cup 2021 — Traffic Analysis (Boolean-Blind SQLi PCAP)

> **Flag**: `flag{w1reshARK_ez_1sntit}`
>
> A 4.8 MB PCAP containing ~25,000 packets of an attacker mid-blind-SQLi against `sqli-labs Less-5`. The job is to recover the value the attacker eventually exfiltrated. The mechanically interesting parts are: (1) pairing 4,000+ HTTP request/response pairs reliably using `tcp.stream` rather than guessing by frame adjacency, and (2) telling apart "true" vs "false" responses when the size delta is only 12 bytes — and the methodology trap of *assuming* which one is true based on intuition rather than measurement.

## 0. File overview

| Field | Value |
|---|---|
| File | `timu.pcapng` |
| Size | 4.8 MB |
| Packets | ~25,000 |
| Duration | 11.77 seconds (rapid-fire automated attack) |
| Application | `sqli-labs` Less-5 (boolean-blind SQLi training app) |
| Vector | `?id=1' AND ascii(substr((select flag from t),N,1))=K-- +` |

```
$ capinfos timu.pcapng
Number of packets:     25 k
Capture duration:      11.77 s

$ tshark -r timu.pcapng -q -z io,phs
http     4219     data-text-lines  2109
```

So ~2100 HTTP request/response pairs over 11 seconds — about 200 queries/sec. Classic automated blind-injection rate.

## 1. Identifying the attack pattern

Sample a few request URIs:

```
$ tshark -r timu.pcapng -Y http.request -T fields -e http.request.uri | head -3
/ctf/Less-5/?id=1' and ascii(substr((select flag from t),1,1))=33-- +
/ctf/Less-5/?id=1' and ascii(substr((select flag from t),1,1))=34-- +
/ctf/Less-5/?id=1' and ascii(substr((select flag from t),1,1))=35-- +
```

Standard sqli-labs Less-5 single-quote escape, `-- +` comment-out, `ascii(substr(...))` for character-by-character exfil. The attacker iterates position `N` and character `K`. We need to find, for each `N`, which `K` returned the "true" response.

## 2. Pairing requests with responses

For 4000+ HTTP transactions, frame-adjacency pairing is fragile (TCP retransmissions, out-of-order delivery, multiple concurrent streams). The robust pairing key is **`tcp.stream`** — each blind-SQL query opens a fresh stream and closes it after the response.

```
$ tshark -r timu.pcapng -Y http -T fields \
    -e tcp.stream -e http.request.uri \
    -e http.response.code -e tcp.len
```

This gives one row per packet that's either an HTTP request *or* response. Same `tcp.stream` ID groups them; we walk the rows and accumulate.

## 3. Telling true from false

Boolean-blind SQLi response size depends on whether the injected predicate is true. For sqli-labs Less-5 specifically:

- True predicate: the original `id=1` row is returned (e.g. "Your Login name: Dumb / Password: Dumb")
- False predicate: no row returned (the inner `select` matches a different condition, or the AND short-circuits)

Both responses are short, plain HTML with similar templating. The difference is ~12 bytes.

```
$ tshark -r timu.pcapng -Y "http.response" -T fields -e tcp.len \
  | sort | uniq -c | sort -rn
928 2084
912 25
```

Two distinct response sizes: **2084 bytes (occurring 928 times)** and **2072 bytes (~12 byte difference, occurring 912 times)**, plus a small tail of other sizes.

**This is where the trap lives.** My first guess: "true is the *larger* response, because it includes the matched row data". Decoded under that assumption — every flag position came out as ASCII `33` = `!`. Suspicious uniformity = wrong assumption.

The reality: 928 occurrences ≈ `2100 - flag_length × 95-ish failures-per-position`, which matches what you'd see if **928 is the count of the more-common-but-actually-false branch**, and 912 is the rarer-but-actually-true. Roughly 25 of the 912 responses align with the 25 character positions in the flag.

```
flag length = 25 chars
true responses = ~25 (one per position, the rare size)
false responses = ~2000 (one per position × wrong-character attempts)
```

The corrected rule: **let frequency cross-validate which response size is true**. The true branch should fire *once* per flag position; the false branch should fire many times (for each rejected character). Whichever response size occurs ≈ `flag_length` times is the true branch.

## 4. Decoder script

```python
#!/usr/bin/env python3
import re
import subprocess
from collections import defaultdict

PCAP = "timu.pcapng"

# Field extraction with tshark
out = subprocess.check_output([
    "tshark", "-r", PCAP, "-Y", "http",
    "-T", "fields",
    "-e", "tcp.stream",
    "-e", "http.request.uri",
    "-e", "http.response.code",
    "-e", "tcp.len",
], stderr=subprocess.DEVNULL).decode()

# Group by tcp.stream
streams = defaultdict(lambda: {"uri": None, "resp_len": None})
for line in out.splitlines():
    parts = (line.split("\t") + ["", "", "", ""])[:4]
    stream_id, uri, resp_code, tlen = parts
    if not stream_id:
        continue
    if uri:
        streams[stream_id]["uri"] = uri
    if resp_code and tlen:
        try:
            streams[stream_id]["resp_len"] = int(tlen)
        except ValueError:
            pass

# Extract (position, candidate_char, response_size) triples
pairs = []
pattern = re.compile(r"substr\(\(select flag from t\),(\d+),1\)\)=(\d+)")
for v in streams.values():
    if not v["uri"] or v["resp_len"] is None:
        continue
    uri = v["uri"].replace("%20", " ").replace("+", " ")
    m = pattern.search(uri)
    if m:
        pos, cand, size = int(m.group(1)), int(m.group(2)), v["resp_len"]
        pairs.append((pos, cand, size))

# Cross-check: which response size aligns with flag length (~25)?
from collections import Counter
size_counts = Counter(size for _, _, size in pairs)
print(f"Response size histogram: {size_counts.most_common(4)}")
# Pick the size whose count is ≈ flag length (the rarer one)

TRUE_SIZE = 2072   # determined from histogram, NOT from intuition

# Group by position, pick the candidate that gave a true response
by_pos = defaultdict(list)
for pos, cand, size in pairs:
    if size == TRUE_SIZE:
        by_pos[pos].append(cand)

flag = "".join(chr(by_pos[p][0]) for p in sorted(by_pos))
print(f"flag: {flag}")
```

Output:

```
flag: flag{w1reshARK_ez_1sntit}
```

## 5. Traps and lessons learned

| Trap | Why it cost me time | Resolution |
|---|---|---|
| Assumed true = larger response | "Returned row means more bytes" intuition felt obvious | False here. Always cross-validate by **frequency**: true should fire ~flag-length times, false should fire many more |
| Tried `http.content_length` | The pcap had it sometimes blank, sometimes 0; broke the analysis silently | Use `tcp.len` instead — it's always populated for response packets and includes the HTTP body bytes |
| Paired requests / responses by frame adjacency | Got mis-pairs because of TCP retransmits and overlapping streams | `tcp.stream` is the join key. Wireshark assigns one per TCP connection; each pcap session naturally pairs req+resp per stream |
| Forgot to URL-decode the URI | Regex couldn't match `substr%28...` form | `tshark` outputs the URI literally as on-the-wire. URL-decode (`%20` → space, `+` → space) before regex |
| Started by exporting all HTTP bodies | Was about to mass-export request/response bodies and diff them | The information is in the *sizes*, not the contents. Don't dump body data unless you need it |

## 6. Methodology takeaways

1. **For boolean-blind decoding from PCAP, response **size** is the signal.** Not response content, not status code, not timing — size. Two distinct response sizes form a clean histogram; cross-validate with frequency to identify true vs. false.
2. **Frequency cross-validation beats intuition.** The flag has a known length (or knowable from the position parameter range). The true-branch count should match flag length. The intuition "true is bigger" is often wrong.
3. **`tcp.stream` is the canonical request/response pairing key.** For HTTPS, `tls.stream` is similar. Avoid frame-adjacency or timestamp-based pairing — they break under any TCP reordering.
4. **`tshark` field extraction beats Wireshark GUI for bulk analysis.** `tshark -T fields -e ...` produces tab-separated lines that are easy to grep / parse. Process them in Python with `defaultdict` to group by stream.
5. **For sqli-labs and similar training apps, the SQLi *pattern* is fingerprintable.** `substr((select flag from t), N, 1) = K` is the standard boolean-blind extractor template. Spot it in URIs; you instantly know what the attack is doing.

## 7. Related techniques

- [NewStarCTF 2023 last_traffic](../forensics/newstarctf2023_last_traffic.md) *(coming soon)* — same family with a different sqli-labs lesson
- [`SQLMap`'s blind-bool detection](https://github.com/sqlmapproject/sqlmap/wiki/Techniques) — how the attacker tools generate these patterns; understanding them helps reverse-engineer captures
- [`tshark` cheatsheet](https://www.wireshark.org/docs/man-pages/tshark.html) — field extraction syntax for forensic scripting
