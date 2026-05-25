# 2025 ZhuJian Cup · Dimensionality Reduction Strike — Writeup

> Round 2 ZhuJian Cup Qualifiers · Misc | 0 solves during contest | Post-contest reproduction

**Flag**: `flag{b9f98204ff63b60d41b30f2a028c96c5}`

---

## Challenge Summary

A "digital rain" style 729×729 PNG (`降维打击.png`), themed around the *Three-Body Problem* concepts of dimensionality strikes and sophon surveillance.

> Task: Peek through dimensional boundaries to find the flag hidden by the sophon.

Key number: 729 = 3⁶, pervasive throughout the challenge.

## Step 1: Extract the Hidden PNG

4575 bytes of trailer data appended after the outer image's IEND chunk form a complete 1200×120 RGBA PNG.

```bash
binwalk -e 降维打击.png        # or foremost
# → inner_extracted.png (1200×120 RGBA)
```

## Step 2: Separate 3 Stacked Frames

The inner image appears as overlapping ghost text—actually 3 frames stacked with a 3-pixel horizontal offset. Separate via sub-pixel phase sampling:

```python
from PIL import Image; import numpy as np

im = Image.open('inner_extracted.png').convert('L')
a = (np.array(im) > 127).astype(np.uint8)

for offset in range(3):
    frame = a[offset::3, offset::3] * 255       # 40×400 effective char resolution
    Image.fromarray(frame).save(f'frame_{offset}.png')
```

The 3 frames reveal:

| Frame | Upper (text) | Lower (WASD path) |
|-------|-------------|-------------------|
| 0 | Snowflakes are all 1.26 dimensions. Why are you a surface | `dwawddss` |
| 1 | How can we break through the boundaries of dimensions | `wwdssdww` |
| 2 | — | `dwawwdsdwdssasd` / `ddwwasawwdddsss` |

## Step 3: Decode the Clues

1. **"1.26 dimensions"** — Koch snowflake fractal dimension log₄/log₃ ≈ 1.262 → hints at **3-adic fractal structure**
2. **"break through the boundaries of dimensions"** — reverse the dimensionality reduction: go from the 2D surface back to the original data
3. **WASD direction sequences** — 4 Hamiltonian paths:
   - `dwawddss` and `wwdssdww` cover a 3×3 grid (Peano curve base templates)
   - `dwawwdsdwdssasd` and `ddwwasawwdddsss` cover a 4×4 grid
4. **729 = 3⁶** — A Peano curve of 6 recursion levels exactly fills a 729×729 square

**Conclusion**: The outer image's pixels have been scrambled according to a Peano space-filling curve traversal order. Place the pixels back in their correct raster positions to recover the original image.

## Step 4: Generate the Peano Curve via L-System

### Why L-System Is Required

Handcrafted recursive Peano construction (cell-by-cell with flip rules) is extremely difficult to get right—adjacent sub-curves must have precisely matching exit/entry orientations. A single incorrect flip rule produces a **jump (Manhattan distance ≠ 1)**, breaking the entire curve.

An L-System with turtle graphics inherently guarantees continuity: after completing each sub-curve, explicit `+` or `-` 90° rotation instructions align the turtle for the next cell, making gaps physically impossible.

### Production Rules

```
Axiom:  X

X  →  X F + Y F Y + F X - F - X F X F X - F Y F Y +
Y  →  - X F X F + Y F Y F Y + F + Y F - X F X - F Y

F   = forward 1 unit
+   = turn left 90°
-   = turn right 90°
```

Each rule describes the turtle's path through a 3×3 sub-grid:
- `X` corresponds to one 9-cell template (enter from left → exit from right)
- `Y` corresponds to the other template (enter from bottom → exit from top)
- After 6 iterations, the turtle visits all 3⁶×3⁶ = 729×729 grid points with **Manhattan distance exactly 1 between every consecutive pair**.

### Generating the Visit Order

```python
rules = {
    'X': 'XF+YFY+FX-F-XFXFX-FYFY+',
    'Y': '-XFXF+YFYFY+F+YF-XFX-FY'
}

def lindenmayer(n: int) -> str:
    axiom = 'X'
    for _ in range(n):
        axiom = ''.join(rules.get(c, c) for c in axiom)
    return axiom

def turtle_to_points(cmd: str):
    x, y, angle = 0, 0, 0
    points = [(x, y)]
    for c in cmd:
        if c == 'F':
            if angle == 0:    x += 1
            elif angle == 90:  y += 1
            elif angle == 180: x -= 1
            elif angle == 270: y -= 1
            points.append((x, y))
        elif c == '+': angle = (angle + 90) % 360
        elif c == '-': angle = (angle - 90) % 360
    return points

order_6 = turtle_to_points(lindenmayer(6))   # 531,441 coordinate pairs
```

## Step 5: Pixel Rearrangement

```python
from PIL import Image

rearr = Image.open('降维打击.png').convert('RGB')
w, h = rearr.size

original = Image.new('RGB', (w, h))
pixels = list(rearr.getdata())

for i, (x, y) in enumerate(order_6):
    if i >= len(pixels):
        break
    # Pillow's y-axis points down; turtle y-axis points up → flip
    original.putpixel((x, h - y - 1), pixels[i])

original.save('flag.png')
```

## Step 6: Scan the QR Code

The output is a 729×729 **QR code** (white-on-black):

```bash
zbarimg -Sqr.enable flag_inverted.png
# QR-Code:flag{b9f98204ff63b60d41b30f2a028c96c5}
```

---

## Key Lessons

| Wrong Approach | Correct Approach |
|---------------|-----------------|
| Handcrafted recursive Peano (cell-by-cell, only y-flipping middle column) → 44,286 jumps | L-System + turtle: `+/-` instructions bridge adjacent cells automatically |
| Hilbert curve (2-adic) → 729 is not a power of 2 | Peano curve (3-adic) → 729 = 3⁶ is an exact match |
| Binarization (>127 threshold) → loses grayscale information | Preserve original 0–255 green channel values |
| Reshape to arbitrary aspect ratios → noise | Restore to original 729×729 dimensions to reveal QR code |

## Toolchain

- `binwalk` / `foremost` — PNG trailer data extraction
- Python + Pillow + NumPy — image processing, 3-frame separation, Peano L-System, pixel rearrangement
- `zbarimg` — QR code scanning

## References

- Challenge source: https://xj.edisec.net/challenges/324
- Inspiration: Bilibili video on *Dimensionality Reduction Strike* + Three-Body sophon unfolding
- Related challenge: QiangWang Cup Threebody (same curve family, uses Hilbert instead of Peano)
