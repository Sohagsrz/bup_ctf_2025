#!/usr/bin/env python3
"""
Step by step analysis - let's understand phase 2 kdata indexing
"""

KDATA = [
    0xa3d94f21, 0x55ccaa01, 0x12345678, 0xdeadbeef,
    0x0f1e2d3c, 0xcafebabe, 0xfeedface, 0x01020304,
    0x89abcdef, 0x13579bdf, 0x2468ace0, 0x0badf00d,
    0x31415926, 0x27182818, 0xb16b00b5, 0x0c0ffee0,
    0xf00dbaaa, 0xbaadf00d, 0xabcd1234, 0x0defaced,
    0xc001d00d, 0xfeedf00d, 0xdeadc0de, 0x1337c0de
]

KEY = 0x28c
MAGIC = 0xAAAAAAAAAAAAAAAB

# Phase 2 assembly analysis:
# 0x1440: mov rax, r9          ; rax = r9
# 0x1443: mov ecx, r8d         ; ecx = r8
# 0x1446: add r8d, 7           ; r8 += 7
# 0x144e: mul r13              ; rax * MAGIC (result in rdx:rax)
# 0x1451: and ecx, 7           ; ecx = r8 & 7 (for shift)
# 0x1454: shr rdx, 4           ; rdx = (high_bits >> 4)
# 0x1458: lea rax, [rdx+rdx*2] ; rax = rdx * 3
# 0x145c: mov rdx, r9          ; rdx = r9
# 0x145f: add r9, 3            ; r9 += 3
# 0x1463: shl rax, 3           ; rax = rax * 8 (total: rdx * 24)
# 0x1467: sub rdx, rax         ; rdx = rdx - rax
# 0x146a: mov edx, [rbp+rdx*4] ; get KDATA[rdx]

# So kdata_idx calculation:
# val = r9
# high_bits = (val * MAGIC) >> 64
# shifted = high_bits >> 4
# offset = (shifted * 3 * 8) = (shifted * 24)
# kdata_idx = (val - offset) % 24

def calculate_kdata_idx_phase2(r9_val):
    """Calculate kdata index for phase 2 using magic number"""
    # The magic number trick: multiply by MAGIC, get high 64 bits
    # For Python, we approximate
    val = r9_val & 0xFFFFFFFFFFFFFFFF
    # Multiply by MAGIC - this is a trick for fast division by 24
    # The result's high bits approximate val / 24
    product = val * MAGIC
    # Get high 64 bits (bits 64-127 of 128-bit result)
    high_bits = (product >> 64) & 0xFFFFFFFFFFFFFFFF
    # Shift right by 4
    shifted = high_bits >> 4
    # Multiply by 3, then by 8 (total: multiply by 24)
    offset = ((shifted + (shifted << 1)) << 3) & 0xFFFFFFFFFFFFFFFF
    # Subtract
    result = (val - offset) & 0xFFFFFFFFFFFFFFFF
    return result % 24

# Test the calculation
print("Testing phase 2 kdata index calculation:")
r9 = (KEY >> 8) & 0xFF  # 0x02
for i in range(5):
    idx = calculate_kdata_idx_phase2(r9)
    print(f"  r9=0x{r9:02x}, kdata_idx={idx}")
    r9 = (r9 + 3) & 0xFF

# Compare with simple modulo
print("\nComparing with simple (r9 * 3) % 24:")
r9 = (KEY >> 8) & 0xFF
for i in range(5):
    idx_simple = (r9 * 3) % 24
    idx_magic = calculate_kdata_idx_phase2(r9)
    match = "✓" if idx_simple == idx_magic else "✗"
    print(f"  r9=0x{r9:02x}, simple={idx_simple}, magic={idx_magic} {match}")
    r9 = (r9 + 3) & 0xFF

