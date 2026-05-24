# Pengcheng Cup 2025 — The Rogue Beacon (CAN-bus chassis-domain forensic)

> A telemetry pcap from an autonomous-driving startup's high-speed test was intercepted by a competitor. Identify the **real** vehicle speed signal among multiple fake "rogue beacon" CAN IDs and report the **exact location** of the peak speed event.

## 0. Artifacts

| File | Type | Role |
|---|---|---|
| `The Rogue Beacon.pcapng` | 779 KB, **SocketCAN linktype 125**, ns timestamps | 16,231 CAN frames over 8.25 s |

Capture metadata: `vcan0` virtual interface, Linux 6.8.11, dumpcap 4.0.7. 36 unique CAN IDs distributed across the chassis domain (100 Hz control loops, 50 Hz sub-systems, 25 Hz broadcasts, sub-10 Hz status reports).

## 1. Two-pass approach

**Pass 1 — Identify the rogue beacons (interference data to discard).** The challenge title is literal: most CAN IDs in this capture are *rogue* — their payload bytes are completely static, and only a single trailing counter byte rolls. They mimic the cadence of real chassis signals but carry no information.

**Pass 2 — Locate the genuine speed signal.** One CAN ID will show smoothly varying bytes with a strong monotonic trend. Decode it, find the peak, and use its **global pcap frame number** as the encoded "location."

## 2. CAN ID frequency map

```bash
tshark -r 'The Rogue Beacon.pcapng' -T fields -e can.id | sort | uniq -c | sort -rn
```

| Tier | Count / 8s | Approx. Hz | Sample IDs |
|---|---|---|---|
| High | ~826 | ~100 Hz | 0x149, 0x319, 0x323, 0x380, 0x387, 0x398, 0x13F, 0x143, 0x17C, 0x18E, 0x183, 0x307–0x401 |
| Mid  | ~413 | ~50 Hz  | 0x1A4, 0x1AA, 0x1B0, 0x1CF, 0x1D0, 0x1DC, 0x420, 0x426, 0x432, 0x464, 0x476 |
| Mid  | ~205, 618, 545 | 25-75 Hz | **0x244** ★, 0x21E, 0x294, 0x39 |
| Sparse | 28-84 | 3-10 Hz | 0x305, 0x309, 0x320, 0x324, 0x333, 0x37C, 0x405, **0x40C** (VIN), 0x428, 0x454, 0x5A1 |

## 3. Rogue-beacon signature

Per-byte range analysis (see `byte-stats` snippet below) reveals the rogue pattern across **most IDs**:

```
0x37C  fd 00 fd 00 09 7f 00 ZZ     ZZ ∈ {0x0B, 0x1A, 0x29, 0x38} cycling
0x324  74 65 00 00 00 00 0e ZZ     same 4-state cycle in last byte only
0x309  00 00 00 00 00 00 00 ZZ     ZZ ∈ {0x84, 0x93, 0xA2, 0xB1}
0x294  04 0b 00 02 cf 5a 00 ZZ     constant prefix + counter
0x21E  03 e8 37 45 22 06 ZZ        idem
0x143  6b 6b 00 ZZ                 idem
0x1A4  00 00 00 08 00 00 00 ZZ     idem
```

**Statistical fingerprint of a rogue beacon**:
- Information bytes: `range == 0` (fully static)
- Trailing byte: high nibble cycles 0–3 (4-state cycle ≈ 0.4 s), low nibble is a 4-bit staleness counter (0–15, ≈ 100 ms)
- Combined trailing-byte range therefore ≈ 0x00–0x3F (or 0x40–0x7F, etc., depending on the high-nibble band)

This is the canonical CAN heartbeat / staleness pattern. Real chassis signals do **not** look like this.

## 4. The real speed signal: 0x244

The only ID with statistically meaningful variation:

```python
0x244 byte3:  range=28  mean=33  std=8.3   mono=+18.8   ★
0x244 byte4:  range=255 mean=129 std=74.4  mono=-0.04
```

`mono` is the difference between last-quarter mean and first-quarter mean — a +18.8 jump in byte 3 indicates a strong rising trend, the signature of a vehicle accelerating from a moderate speed to its peak.

Inspecting consecutive frames reveals byte 3 as the **high byte** of a 16-bit big-endian counter and byte 4 as the **low byte**:

```
idx   t(s)    byte3 byte4   BE 16-bit   diff
  0   0.013    27   22       6934
  1   0.024    27    4       6916        -18
  2   0.041    26  241       6897        -19    (byte 3 carried)
  3   0.057    26  223       6879        -18
```

Smooth ±18 steps per frame across a byte-3 boundary → unambiguous BE 16-bit encoding.

### Scaling

Try standard CAN speed scale factors against the raw peak (13796):

| Factor | Peak in km/h | Plausibility |
|---|---|---|
| `× 0.01` | **137.96** | ✅ realistic for a chassis stress test |
| `× 1/256` | 53.89 | ✗ too slow for a "limit test" |
| `× 1/16` | 862.25 | ✗ unphysical |

**Decoded formula**: `speed_kmh = ((byte3 << 8) | byte4) × 0.01`

### Full speed curve

```
t=0.01s:  69.34 km/h   (start of capture)
t=3.0s : 100.84
t=5.4s : 126.91
t=6.18s: 137.96 km/h  ★ peak
t=6.4s : 134.52       (deceleration begins)
t=8.0s : 112.79       (end of capture)
```

A clean acceleration → brief peak → deceleration profile, consistent with a limit-speed test maneuver.

## 5. Locating the peak — what "exact location" means

GPS coordinates were the first guess. Exhaustive scan of all IDs for 32-bit signed int / float / smoothly varying multi-byte signals **found nothing matching geographic coordinates**. The 0x40C multi-frame stream decodes to a VIN (`JHMFA3%6229S0913849`, Honda Civic 2009 family), but that's static metadata.

In CAN-forensic context, "exact location" maps to the **pcap global frame number** of the peak event — the natural cross-reference for any chassis log analyzer.

```bash
tshark -r 'The Rogue Beacon.pcapng' -Y 'can.id==0x244' \
  -T fields -e frame.number -e data > can244.tsv
```

```python
rows = []
for line in open("can244.tsv"):
    fn, hexd = line.strip().split("\t")
    d = bytes.fromhex(hexd.replace(":",""))
    rows.append((int(fn), (d[3] << 8) | d[4]))

peak_fn, peak_raw = max(rows, key=lambda r: r[1])
# peak_raw = 13796 (137.96 km/h)
# peak_fn  = 12149
```

## 6. Flag — SHA256 of the frame number

```python
import hashlib
flag = "flag{" + hashlib.sha256(str(12149).encode()).hexdigest() + "}"
# flag{9db878fd06dd7587a91c0fb600e0e9f7c3ea310e75f36253ef57ac2d92dd8c29}
```

## 7. End-to-end one-liner

```bash
tshark -r 'The Rogue Beacon.pcapng' -Y 'can.id==0x244' \
  -T fields -e frame.number -e data \
| python3 -c "
import sys, hashlib
m = max(((int(p[0]), (bytes.fromhex(p[1].replace(':',''))[3]<<8)|bytes.fromhex(p[1].replace(':',''))[4])
        for p in (l.strip().split('\t') for l in sys.stdin) if len(p)==2), key=lambda x: x[1])
print(f'peak={m[1]*0.01:.2f} km/h @ frame {m[0]}')
print('flag{' + hashlib.sha256(str(m[0]).encode()).hexdigest() + '}')
"
```

## 8. CAN signal triage — reusable methodology

For any unknown CAN capture, the workflow that solved this challenge generalizes:

```python
# 1. Group by CAN ID
by_id = defaultdict(list)
for ts, cid, d in frames: by_id[cid].append((ts-t0, d))

# 2. For each ID × each byte position × each width (1B / 2B BE / 2B LE), compute:
#    - range       (max - min)
#    - smoothness  (mean abs frame-to-frame diff)
#    - mono_diff   (last-quartile mean - first-quartile mean, captures trend)
# A real continuous signal has: large range, small relative smoothness, large |mono_diff|.
# A rogue beacon has: range ≈ 0 on info bytes, range ≤ 0x3F on a single trailing byte.

def is_real_signal(rng, smooth, mono):
    return rng > 50 and smooth < rng/20 and abs(mono) > rng/5

# 3. Once a candidate byte tuple is flagged, identify endianness by checking carry
#    behavior: when low byte wraps 255→0, high byte should ±1.

# 4. Determine scale by testing standard CAN factors {1, 0.1, 0.01, 1/256, 1/16}
#    against expected physical range for the suspected signal.
```

## 9. Pitfalls

1. **"位置" (location) is ambiguous in Chinese**. It can mean GPS coordinates, frame number, or timestamp. Test all three interpretations before committing to a search direction. CAN-forensic context overwhelmingly means **frame number**.
2. **High frequency ≠ informative**. Many 100 Hz IDs in this capture are pure heartbeats. Frequency tells you the message exists; statistical variance tells you it carries information.
3. **Multi-frame ASCII in 0x40C** decodes to a Honda VIN — recognize the sub-frame index byte pattern (`01/02/03/00` cycling) even when it doesn't strictly match ISO 15765-2 ISO-TP framing.
4. **Don't brute-force scale factors blindly**. Try the three canonical CAN factors (0.01, 1/256, 1/16) and accept the one that yields a physically reasonable result.

## 10. Toolchain

| Tool | Purpose |
|---|---|
| `tshark` | extract `can.id`, `can.len`, raw data bytes; filter by ID |
| `capinfos` | confirm SocketCAN linktype and packet counts |
| Python + `struct` | per-byte time series, endianness probing, scale detection |
| `hashlib.sha256` | recover the flag from the frame number |

No specialized CAN tooling (CANalyzer / CANoe / Wireshark CAN dissector beyond default) is required — pure `tshark` + Python is sufficient for triage-grade analysis of an 8-second / 16k-frame capture.
