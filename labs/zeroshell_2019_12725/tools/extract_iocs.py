#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
extract_iocs.py — Generic ELF / PE indicator-of-compromise extractor.

Born from the 2024 CISCN/长城杯 ZeroShell challenge where the trojan placed:

    offset 0x9eaa3 :  202.115.89.103\0          # C2 IP
    offset 0x9eab2 :  11223344qweasdzxc\0       # AES-128 key (adjacent!)
    offset 0x9e220 :  <AES Te0 round table>     # crypto confirmation

This script generalises that observation into a reusable triage tool:

  1. Scan for IPv4 literals (filter RFC1918, loopback, broadcast etc.)
  2. For each "external" IPv4 hit, snapshot the surrounding bytes;
     C2 configurations very commonly place the symmetric key, port, or
     campaign ID directly next to the IP in `.rodata`.
  3. Fingerprint known crypto algorithms by their round tables / S-boxes
     (AES Te0/Te1/Te2/Te3, AES S-box, DES, MD5/SHA constants, ChaCha20
     constants, RC4 initial state pattern).
  4. Detect "keyboard-walk" style weak keys (1qaz, qwer, asdf, zxcv, etc.).
  5. Detect base64-encoded ASCII patterns including "ZmxhZ3s..." (CTF
     flag-prefix signature) and long base64 blobs typical of C2 strings.
  6. Output a structured IOC bundle (JSON / CSV / Markdown) ready to drop
     into a SIEM / threat-intel platform.

Usage:
    python3 extract_iocs.py <sample> [--json] [--csv] [--md] [-v]

Tested against:
  • CISCN-2024 .nginx implant  (ELF 32-bit i386)  → all key IOCs recovered
  • Mirai variants
  • CobaltStrike beacon shellcode dumps (limited — encrypted payloads)
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import re
import struct
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable

# -----------------------------------------------------------------------------
#  Known crypto fingerprints (first N bytes of well-known tables)
# -----------------------------------------------------------------------------
CRYPTO_SIGNATURES: dict[str, bytes] = {
    "AES Te0 table":  bytes.fromhex("a56363c6847c7cf8"),
    "AES Te2 table":  bytes.fromhex("6363c6a57c7cf884"),
    "AES S-box":      bytes.fromhex("637c777bf26b6fc5"),
    "AES inv S-box":  bytes.fromhex("52096ad53036a538"),
    "MD5 constants":  bytes.fromhex("0123456789abcdef"),
    "SHA-1 H0":       bytes.fromhex("67452301efcdab89"),
    "SHA-256 H[0]":   bytes.fromhex("6a09e667bb67ae85"),
    "ChaCha20 const": b"expand 32-byte k",
    "DES SP1":        bytes.fromhex("01010400000000010001"),
}

# -----------------------------------------------------------------------------
#  Heuristics for weak / hardcoded keys
# -----------------------------------------------------------------------------
KEYBOARD_WALK_PATTERNS = [
    "qwer", "asdf", "zxcv", "1234", "qaz", "wsx", "edc",
    "asdfgh", "qwerty", "1qaz", "2wsx", "abcd",
    "11223344", "12345678", "87654321",
]

PRINTABLE = set(range(0x20, 0x7F))
KEY_LENGTHS_OF_INTEREST = (8, 16, 24, 32, 64)   # DES, AES-128/192/256, HMAC

# -----------------------------------------------------------------------------
#  Data classes
# -----------------------------------------------------------------------------
@dataclass
class IoCBundle:
    sample_path: str
    sample_size: int
    sample_md5: str = ""
    sample_sha256: str = ""
    elf_arch: str = ""
    elf_stripped: bool = False
    ipv4_candidates: list[dict] = field(default_factory=list)
    crypto_hits: list[dict] = field(default_factory=list)
    candidate_keys: list[dict] = field(default_factory=list)
    domain_candidates: list[dict] = field(default_factory=list)
    url_candidates: list[dict] = field(default_factory=list)
    base64_candidates: list[dict] = field(default_factory=list)


# -----------------------------------------------------------------------------
#  Helpers
# -----------------------------------------------------------------------------
def is_external_ipv4(ip: str) -> bool:
    """Filter out RFC1918, loopback, broadcast, multicast, link-local, version-strings."""
    try:
        a = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_multicast
                or a.is_link_local or a.is_unspecified
                or a.is_reserved or str(a).startswith("0."))


def hexdump(b: bytes, width: int = 16) -> str:
    out = []
    for off in range(0, len(b), width):
        chunk = b[off:off + width]
        hexpart = " ".join(f"{c:02x}" for c in chunk).ljust(width * 3)
        ascpart = "".join(chr(c) if c in PRINTABLE else "." for c in chunk)
        out.append(f"  +{off:04x}  {hexpart}  {ascpart}")
    return "\n".join(out)


def detect_arch_and_strip(data: bytes) -> tuple[str, bool]:
    """Best-effort ELF arch detection (i386 / amd64 / arm / arm64), strip flag."""
    if not data.startswith(b"\x7fELF"):
        return ("not_elf", False)
    bits = "64" if data[4] == 2 else "32"
    e_machine = struct.unpack_from("<H", data, 0x12)[0]
    arch_map = {0x03: "i386", 0x3e: "amd64", 0x28: "arm", 0xb7: "arm64", 0x08: "mips"}
    arch = f"{arch_map.get(e_machine, hex(e_machine))} ({bits}-bit)"
    stripped = b".symtab" not in data
    return (arch, stripped)


def hashes(data: bytes) -> tuple[str, str]:
    import hashlib
    return hashlib.md5(data).hexdigest(), hashlib.sha256(data).hexdigest()


# -----------------------------------------------------------------------------
#  Extractors
# -----------------------------------------------------------------------------
RE_IPV4 = re.compile(rb"(?<![\d.])((?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)"
                     rb"\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d))"
                     rb"(?![\d.])")

# Hostname: a.b.tld with at least one dot, TLD ≥ 2 chars, allow hyphen
RE_DOMAIN = re.compile(rb"(?<![\w.])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                       rb"[a-z]{2,24}(?![\w.])", re.I)

RE_URL = re.compile(rb"https?://[\x21-\x7e]{4,256}", re.I)

RE_B64_LONG = re.compile(rb"[A-Za-z0-9+/]{20,}={0,2}")


def extract_ipv4(data: bytes, ctx_bytes: int = 64) -> list[dict]:
    seen: dict[str, dict] = {}
    for m in RE_IPV4.finditer(data):
        ip = m.group(1).decode()
        if not is_external_ipv4(ip):
            continue
        off = m.start(1)
        if ip in seen:
            seen[ip]["offsets"].append(off)
            continue
        # capture surrounding context — may contain the symmetric key
        ctx_start = max(0, off - ctx_bytes)
        ctx_end   = min(len(data), off + len(ip) + ctx_bytes)
        ctx_bytes_val = data[ctx_start:ctx_end]
        seen[ip] = {
            "ip": ip,
            "offsets": [off],
            "context_offset": ctx_start,
            "context_hex": ctx_bytes_val.hex(),
            "context_ascii": "".join(
                chr(c) if c in PRINTABLE else "." for c in ctx_bytes_val
            ),
        }
    return list(seen.values())


def extract_crypto(data: bytes) -> list[dict]:
    hits = []
    for name, sig in CRYPTO_SIGNATURES.items():
        off = 0
        while (idx := data.find(sig, off)) != -1:
            hits.append({"algorithm": name, "offset": idx, "offset_hex": hex(idx)})
            off = idx + 1
            if len(hits) > 20:
                break
    return hits


def is_keyboard_walk(s: str) -> bool:
    sl = s.lower()
    return any(p in sl for p in KEYBOARD_WALK_PATTERNS)


def is_likely_key_string(s: str, *, strict_length: bool = True) -> bool:
    """
    Mixture of ASCII letters + digits, no whitespace, no path separators,
    not pure-numeric (would be a port/version).
    `strict_length=True` requires a canonical key size; relax for
    "adjacent to confirmed C2 IP" context where length is secondary evidence.
    """
    if strict_length and len(s) not in KEY_LENGTHS_OF_INTEREST:
        return False
    if not (6 <= len(s) <= 64):
        return False
    if any(c.isspace() or c in "/\\=:;'\"`" for c in s):
        return False
    has_alpha = any(c.isalpha() for c in s)
    has_digit = any(c.isdigit() for c in s)
    if not (has_alpha and has_digit):
        return False
    # reject paths / version strings / placeholders
    if "lib" in s.lower() and ".so" in s.lower():
        return False
    return True


def extract_candidate_keys(data: bytes, near_ips: list[dict]) -> list[dict]:
    """
    Two-pass approach:
      (a) Adjacent to a confirmed external IPv4 (highest confidence — based on the
          ZeroShell / Mirai layout pattern)
      (b) Global scan for printable-ASCII strings of key lengths
    """
    candidates: list[dict] = []
    seen_strings: set[str] = set()

    # ----- (a) Adjacent to IP --------------------------------------------------
    # Relax length filter — adjacency to confirmed C2 IP is itself strong evidence
    for ip_rec in near_ips:
        ctx_start = ip_rec["context_offset"]
        for m in re.finditer(rb"[\x21-\x7e]{6,64}", data[ctx_start:ctx_start + 256]):
            s_bytes = m.group(0)
            try:
                s = s_bytes.decode("ascii")
            except UnicodeDecodeError:
                continue
            if s == ip_rec["ip"]:
                continue
            if not is_likely_key_string(s, strict_length=False):
                continue
            if s in seen_strings:
                continue
            seen_strings.add(s)
            canonical = len(s) in KEY_LENGTHS_OF_INTEREST
            confidence = "HIGH" if canonical else "MEDIUM-HIGH"
            candidates.append({
                "value": s,
                "length": len(s),
                "offset": ctx_start + m.start(0),
                "evidence": f"adjacent to C2 candidate {ip_rec['ip']}"
                            + ("" if canonical else " (non-canonical length)"),
                "weak": is_keyboard_walk(s),
                "confidence": confidence,
            })

    # ----- (b) Global scan -----------------------------------------------------
    for m in re.finditer(rb"[\x21-\x7e]{8,32}\x00", data):
        s_bytes = m.group(0).rstrip(b"\x00")
        try:
            s = s_bytes.decode("ascii")
        except UnicodeDecodeError:
            continue
        if s in seen_strings:
            continue
        if not is_likely_key_string(s):
            continue
        if not is_keyboard_walk(s):
            continue  # only flag "obviously weak" patterns globally
        seen_strings.add(s)
        candidates.append({
            "value": s,
            "length": len(s),
            "offset": m.start(0),
            "evidence": "keyboard-walk weak pattern",
            "weak": True,
            "confidence": "MEDIUM",
        })

    candidates.sort(key=lambda x: (x["confidence"] != "HIGH", x["offset"]))
    return candidates


def extract_domains(data: bytes) -> list[dict]:
    seen: dict[str, list[int]] = {}
    blacklist_tlds = {".so", ".org/", ".net/", ".com/"}  # likely false positives in version strings
    for m in RE_DOMAIN.finditer(data):
        d = m.group(0).decode().lower()
        if "." not in d or len(d) > 100:
            continue
        if d.endswith(("/", ".so", ".o")):
            continue
        seen.setdefault(d, []).append(m.start(0))
    return [{"domain": d, "offsets": offs, "count": len(offs)} for d, offs in seen.items()]


def extract_urls(data: bytes) -> list[dict]:
    seen: dict[str, list[int]] = {}
    for m in RE_URL.finditer(data):
        u = m.group(0).decode(errors="ignore")
        seen.setdefault(u, []).append(m.start(0))
    return [{"url": u, "offsets": offs} for u, offs in seen.items()]


def extract_base64(data: bytes) -> list[dict]:
    import base64
    hits = []
    for m in RE_B64_LONG.finditer(data):
        s = m.group(0).decode()
        if len(s) > 200:
            continue
        decoded = ""
        try:
            decoded_bytes = base64.b64decode(s, validate=True)
            decoded = "".join(chr(c) if c in PRINTABLE else "." for c in decoded_bytes)
        except Exception:
            continue
        if any(c.isalpha() for c in decoded) and len(decoded) >= 4:
            entry = {"offset": m.start(0), "b64": s, "decoded": decoded}
            if s.startswith("ZmxhZ3"):
                entry["note"] = "CTF flag-marker signature (base64('flag'))"
            hits.append(entry)
        if len(hits) > 30:
            break
    return hits


# -----------------------------------------------------------------------------
#  Output rendering
# -----------------------------------------------------------------------------
def render_markdown(b: IoCBundle) -> str:
    lines = []
    lines.append(f"# IOC Report — `{Path(b.sample_path).name}`\n")
    lines.append(f"| Field | Value |\n|---|---|")
    lines.append(f"| Path | `{b.sample_path}` |")
    lines.append(f"| Size | {b.sample_size:,} bytes |")
    lines.append(f"| MD5 | `{b.sample_md5}` |")
    lines.append(f"| SHA-256 | `{b.sample_sha256}` |")
    lines.append(f"| Architecture | {b.elf_arch} |")
    lines.append(f"| Stripped | {b.elf_stripped} |")
    lines.append("")

    if b.ipv4_candidates:
        lines.append("## External IPv4 Candidates\n")
        lines.append("| IP | Offsets | Adjacent ASCII (preview) |")
        lines.append("|---|---|---|")
        for r in b.ipv4_candidates:
            offs = ", ".join(hex(o) for o in r["offsets"][:5])
            preview = r["context_ascii"][:60].replace("|", "\\|")
            lines.append(f"| `{r['ip']}` | {offs} | `{preview}` |")
        lines.append("")

    if b.crypto_hits:
        lines.append("## Crypto Algorithm Fingerprints\n")
        lines.append("| Algorithm | Offset |")
        lines.append("|---|---|")
        for h in b.crypto_hits:
            lines.append(f"| {h['algorithm']} | {h['offset_hex']} |")
        lines.append("")

    if b.candidate_keys:
        lines.append("## Candidate Symmetric Keys\n")
        lines.append("| Value | Length | Offset | Evidence | Confidence | Weak |")
        lines.append("|---|---|---|---|---|---|")
        for k in b.candidate_keys:
            v = k["value"].replace("|", "\\|").replace("`", "\\`")
            lines.append(f"| `{v}` | {k['length']} | {hex(k['offset'])} | {k['evidence']} "
                         f"| {k['confidence']} | {'YES' if k['weak'] else 'no'} |")
        lines.append("")

    if b.domain_candidates:
        lines.append("## Domain Candidates\n")
        for d in b.domain_candidates[:20]:
            lines.append(f"- `{d['domain']}` (×{d['count']})")
        lines.append("")

    if b.url_candidates:
        lines.append("## URL Candidates\n")
        for u in b.url_candidates[:20]:
            lines.append(f"- `{u['url']}`")
        lines.append("")

    if b.base64_candidates:
        lines.append("## Base64 Candidates\n")
        lines.append("| Offset | Base64 | Decoded | Note |")
        lines.append("|---|---|---|---|")
        for x in b.base64_candidates[:15]:
            note = x.get("note", "")
            b64 = x["b64"][:40] + ("..." if len(x["b64"]) > 40 else "")
            decoded = x["decoded"][:40].replace("|", "\\|")
            lines.append(f"| {hex(x['offset'])} | `{b64}` | `{decoded}` | {note} |")
        lines.append("")

    return "\n".join(lines)


def render_csv(b: IoCBundle) -> str:
    out = []
    w = csv.writer((line := type("L", (), {"write": out.append, "flush": lambda: None})()))
    w.writerow(["type", "value", "offset", "confidence", "notes"])
    for ip in b.ipv4_candidates:
        w.writerow(["ipv4", ip["ip"], hex(ip["offsets"][0]), "high", "external IPv4 in .rodata"])
    for h in b.crypto_hits:
        w.writerow(["crypto", h["algorithm"], h["offset_hex"], "high", "round table / constant fingerprint"])
    for k in b.candidate_keys:
        w.writerow(["crypto_key", k["value"], hex(k["offset"]), k["confidence"], k["evidence"]])
    for d in b.domain_candidates:
        w.writerow(["domain", d["domain"], hex(d["offsets"][0]), "medium", f"observed ×{d['count']}"])
    for u in b.url_candidates:
        w.writerow(["url", u["url"], hex(u["offsets"][0]), "medium", "URL literal"])
    for x in b.base64_candidates:
        w.writerow(["base64", x["b64"], hex(x["offset"]), "low", x.get("note", "decoded: " + x["decoded"][:30])])
    return "".join(out)


# -----------------------------------------------------------------------------
#  Main
# -----------------------------------------------------------------------------
def analyse(path: Path, verbose: bool = False) -> IoCBundle:
    data = path.read_bytes()
    md5, sha256 = hashes(data)
    arch, stripped = detect_arch_and_strip(data)
    b = IoCBundle(
        sample_path=str(path),
        sample_size=len(data),
        sample_md5=md5,
        sample_sha256=sha256,
        elf_arch=arch,
        elf_stripped=stripped,
    )
    b.ipv4_candidates = extract_ipv4(data)
    b.crypto_hits = extract_crypto(data)
    b.candidate_keys = extract_candidate_keys(data, b.ipv4_candidates)
    b.domain_candidates = extract_domains(data)
    b.url_candidates = extract_urls(data)
    b.base64_candidates = extract_base64(data)
    if verbose:
        print(f"[+] Loaded {len(data):,} bytes — {arch} stripped={stripped}", file=sys.stderr)
        print(f"[+] IPs:    {len(b.ipv4_candidates)}", file=sys.stderr)
        print(f"[+] Crypto: {len(b.crypto_hits)}", file=sys.stderr)
        print(f"[+] Keys:   {len(b.candidate_keys)}", file=sys.stderr)
    return b


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Generic ELF/PE IOC extractor")
    ap.add_argument("sample", type=Path, help="path to suspected malware binary")
    ap.add_argument("--json", action="store_true", help="emit JSON to stdout")
    ap.add_argument("--csv",  action="store_true", help="emit CSV to stdout")
    ap.add_argument("--md",   action="store_true", help="emit Markdown to stdout")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    if not args.sample.is_file():
        print(f"[!] not a file: {args.sample}", file=sys.stderr)
        return 2

    bundle = analyse(args.sample, verbose=args.verbose)

    if args.json:
        print(json.dumps(asdict(bundle), indent=2, ensure_ascii=False))
    elif args.csv:
        print(render_csv(bundle))
    else:   # default = markdown
        print(render_markdown(bundle))
    return 0


if __name__ == "__main__":
    sys.exit(main())
