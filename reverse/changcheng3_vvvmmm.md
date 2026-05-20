---
type: source
created: 2026-05-19
updated: 2026-05-19
related: [[sources/changcheng3_vvvmmm]]
---

# Great Wall Cup 3rd — vvvmmm (English)

UPX-packed 64-bit ELF crackme. The full **Unicorn engine** is statically linked; once unpacked it runs a **RISC-V 64-bit VM** to verify a 48-character user input. The VM bytecode is XOR-decrypted at runtime, then computes a Java-style polynomial hash over a **hardcoded key** `e4Y8YRXVzg2HRrCUy35CM0Txq91HzMGZ`, runs 6 rounds of modular exponentiation (mod p = `0x13579BDF`) to produce 12 32-bit "stream words", and **XORs each stream word with a 4-byte slice of the user input**; the 12 XOR results must each match a hardcoded `lui+addi` constant for success.

Concepts: [[concepts/upx-unpacking]], [[concepts/unicorn-embedded-vm]], [[concepts/riscv-modular-hash-check]]

## Flag

`flag{fANUES0XtUXBDEbOXs4xFcXDb3Q5kMU87bZLMZJfuRnCvfwX}`

## Stages

### 1. UPX unpack

```bash
upx -d vvvmmm -o vvvmmm.unpacked   # 1.1 MB → 2.6 MB, static, stripped
```

### 2. Identify Unicorn

```bash
strings vvvmmm | grep -E 'unicorn|uc_riscv|UC_ERR_'
# → unicorn-engine/unicorn, uc_riscv_exit, UC_ERR_OK …
```

### 3. RE the Unicorn init sequence

```
uc_open(8=RISCV, 8=RISCV64)
uc_mem_map(0, 0x1000, ALL); uc_mem_write(0, VM_CODE, 662)
uc_reg_write(SP=3, &0x7000ff00)
uc_mem_map(0x10000000, 0x1000, ALL); uc_mem_write(0x10000000, user_input, 48)
uc_mem_map(0x10001000, 0x1000, ALL); uc_mem_write(0x10001000, KEY_STR, 32)
uc_reg_write(0xb, &0x10000000)          # id 0xB = X10 = a0 = USER INPUT ★
uc_reg_write(0xc, &0x10001000)          # id 0xC = X11 = a1 = KEY        ★
uc_emu_start(0, 662, timeout=2e6)
uc_reg_read(0xb, &result)               # read a0
cmp result, 0; cmove eax, 0x7cf2be54     # a0==0 → "Try again"
                                          # a0!=0 → success path
```

**★ The big trap**: in `UC_RISCV_REG` the enum starts at `INVALID = 0`, so `0xB = 11 = X10 = a0` and `0xC = 12 = X11 = a1`. The host's `uc_reg_write` order is the ground truth — don't intuit the input/key role from your prior RISC-V CTF habits.

### 4. Dump the VM bytecode (after the host's XOR decryption)

The host runs an XOR loop at `0x4021cf` that decrypts the data region `0x64c3f0..0x64cbd2` in place, **including the key string at `0x64c6c0`**. Break at `*0x40205d` (the `call uc_mem_write` for VM code) and read `$ecx` bytes from `$rdx`.

A second breakpoint at `*0x402111` (uc_mem_write for the key buffer) yields the cleartext key `e4Y8YRXVzg2HRrCUy35CM0Txq91HzMGZ`.

### 5. Capstone disassembly

```python
md = capstone.Cs(capstone.CS_ARCH_RISCV,
                 capstone.CS_MODE_RISCV64 | capstone.CS_MODE_RISCVC)
```

Algorithm:

```
hash_loop (0x0C–0x24):    # walks a1 = KEY string
    while (*a1) {
        a3 = a4 - *a1
        a4 = (a4 << 5) - a3 = 31·a4 + *a1     # Java-style base-31 hash, init = 1
        a1++
    }

modular_setup (0x2A–0x40):
    a7 = 0x1357A000 - 0x421 = 0x13579BDF       # modulus p
    sp[0x34] = p; t0..t6, s0..s4 ← p           # 12 copies of the modulus

outer_loop (6 iters, bne a1, a6, -0x15C):
    x = (h >> 16) mod p, b = h mod p
    repeated mul+remu rounds   → a2 = x^M_i mod p, a4 = b^N_i mod p

    # ★ a0 = user-input pointer (set by host)
    sp[a1_local - 4] = INPUT[a0-4..a0]    XOR a2_low32   ★ input slice XOR stream word
    sp[a1_local]     = INPUT[a0..a0+4]    XOR a4_low32
    a0 += 8           # advance input pointer

verify (0x1AA–0x23E):
    t3 = sp[0x04] XOR 0x45034F63
    t4 = sp[0x08] XOR 0x534762D2
    t5 = sp[0x0C] XOR 0x44B36D04
    t0 = sp[0x10] XOR 0x44C3ED6A
    ... 12 checks total

seqz_cascade (0x23E–0x286):
    count = Σ (reg_i == 0)
    a0 = (count - 12 == 0) ? 1 : 0      # success ⟺ all 12 zero
```

### 6. Derive input

For each `i ∈ [0, 12)`:
```
sp[X_i] = INPUT_word_i XOR a_mod_i
condition: sp[X_i] = const_i
⟹ INPUT_word_i = const_i XOR a_mod_i
```

`a_mod_i` depends only on the **hardcoded key's hash**, not on the input. Run the VM once with input = all zeros, capture the 12 sp writes (those values are exactly the `a_mod` stream because anything XOR 0 = itself), then XOR with the 12 `lui+addi` constants:

```python
from unicorn import *
from unicorn.riscv_const import *
import struct

KEY = b'e4Y8YRXVzg2HRrCUy35CM0Txq91HzMGZ'
code = open('/tmp/vm.bin','rb').read()

mu = Uc(UC_ARCH_RISCV, UC_MODE_RISCV64)
mu.mem_map(0, 0x1000, UC_PROT_ALL); mu.mem_write(0, code)
mu.mem_map(0x10000000, 0x1000, UC_PROT_ALL); mu.mem_write(0x10000000, b'\x00'*48)
mu.mem_map(0x10001000, 0x1000, UC_PROT_ALL); mu.mem_write(0x10001000, KEY + b'\x00')
mu.mem_map(0x70000000, 0x10000, UC_PROT_ALL)
mu.reg_write(UC_RISCV_REG_SP, 0x7000ff00)
mu.reg_write(UC_RISCV_REG_A0, 0x10000000)   # ★ a0 = input
mu.reg_write(UC_RISCV_REG_A1, 0x10001000)   # ★ a1 = key

stack_writes = {}
mu.hook_add(UC_HOOK_MEM_WRITE,
            lambda uc, _, addr, size, val, __:
                stack_writes.setdefault(addr, val & 0xffffffff))
mu.emu_start(0, len(code), timeout=5_000_000)

consts = [0x45034F63, 0x534762D2, 0x44B36D04, 0x44C3ED6A,
          0x79BB60B0, 0x42A1E767, 0x3EDB7E6C, 0x30E1551D,
          0x4D3ABAA4, 0x6AA29948, 0x51CE8847, 0x51623FAF]
fsp = 0x7000ff00 - 0x60
flag_input = b''.join(
    struct.pack('<I', consts[i] ^ stack_writes[fsp + 4 + i*4])
    for i in range(12))
print(flag_input)   # b'fANUES0XtUXBDEbOXs4xFcXDb3Q5kMU87bZLMZJfuRnCvfwX'
```

### 7. Verify

```bash
echo 'fANUES0XtUXBDEbOXs4xFcXDb3Q5kMU87bZLMZJfuRnCvfwX' | /tmp/vvvmmm
# input %48c>Good.
# flag{fANUES0XtUXBDEbOXs4xFcXDb3Q5kMU87bZLMZJfuRnCvfwX}
```

## Pitfalls

- **UC_RISCV_REG numbering vs RISC-V ABI alias**: the enum starts at `INVALID = 0`, so `0xB = 11 = X10 = a0` (parameter 1), `0xC = 12 = X11 = a1` (parameter 2). Always read the host's `uc_reg_write` order — don't intuit input/key from prior CTF habits where "a0 = result, a1 = input" is common.
- **Never assume an in-VM register starts at zero**: `c.addi a0, 4` plus `lw a3, -4(a0)` looks like it reads VM code at offset 0 if you assume `a0 = 0`, but `a0` was just set by the host to the input pointer, so the read actually slices user input. I lost a lot of time on a phantom "high-bit contradiction" because of this single mistake.
- **`upx -t` returning OK means the file IS packed** (not "healthy"). Unpacked files report "not packed".
- **Dump VM bytecode after the XOR decrypt loop** (`0x4021cf`); set the gdb breakpoint at the `call uc_mem_write` site so the data segment is already decrypted.
- **Capstone RISC-V needs `MODE_RISCV64 | MODE_RISCVC`** or every 16-bit compressed instruction is reported as `.insn` junk.
- **`r2 -q -c "s ADDR; pd N"`** can disassemble from mid-instruction and skew offsets — start from `s 0; pd N | grep -A` for correctness.

## TL;DR

The VM hashes a binary-embedded key string (NOT the user input), uses that hash to seed a modular RNG that emits 12 stream words, then XORs those stream words against the user input split into 4-byte slices; the XOR results must each match a hardcoded `lui+addi` constant. Solve = run the VM once with input = 0 to extract the 12 stream words, XOR each with its constant to get the required input bytes.

Chinese version: [[sources/changcheng3_vvvmmm]]
