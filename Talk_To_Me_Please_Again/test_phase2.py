#!/usr/bin/env python3
"""
Test phase 2 forward and reverse
"""

from solve_correct import *

# Test phase 2 with output from phase 1
test = b"A" * 29

# Do phase 1 first
stack = bytearray(test)
r12 = KEY & 0xF
r15 = KEY & 0xFFFF
for i in range(len(test)):
    val = (r12 + i) & 0xFFFFFFFFFFFFFFFF
    kdata_idx = calc_kdata_idx_magic(val)
    shift = (i * 5) & 0xf
    kdata_byte = (KDATA[kdata_idx] >> shift) & 0xff
    if i > 0:
        stack[i] ^= stack[i-1]
    stack[i] ^= kdata_byte
    key_shift = (r15 >> (i & 3)) & 0xff
    stack[i] = (stack[i] + key_shift) & 0xff
    stack[i] = ((stack[i] << 3) | (stack[i] >> 5)) & 0xff

phase1_out = bytes(stack)
print(f"After phase 1: {phase1_out.hex()[:40]}...")

# Phase 2 forward
stack = bytearray(phase1_out)
r11 = KEY & 0xFFFF
r9 = (KEY >> 8) & 0xFF
r8 = 0

print(f"\nPhase 2 forward:")
print(f"  Initial: r11=0x{r11:x}, r9=0x{r9:x}, r8={r8}")

for i in range(len(test)):
    kdata_idx = calc_kdata_idx_magic(r9)
    shift = (r8 * 7) & 0x7
    kdata_byte = (KDATA[kdata_idx] >> shift) & 0xff
    before = stack[i]
    stack[i] ^= kdata_byte
    after_xor = stack[i]
    stack[i] = (stack[i] + (r11 & 0xff)) & 0xff
    after_add = stack[i]
    r11 = (r11 + 0xb) & 0xFFFF
    stack[i] = ((stack[i] << 1) | (stack[i] >> 7)) & 0xff
    after_rol = stack[i]
    r9 = (r9 + 3) & 0xFF
    r8 += 7
    if i < 3:
        print(f"  i={i}: 0x{before:02x} -> XOR kdata(0x{kdata_byte:02x}, idx={kdata_idx}) -> 0x{after_xor:02x} -> +0x{r11-0xb:02x} -> 0x{after_add:02x} -> ROL1 -> 0x{after_rol:02x} (r9=0x{r9-3:02x}, r8={r8-7})")

phase2_out = bytes(stack)
print(f"\nAfter phase 2: {phase2_out.hex()[:40]}...")

# Phase 2 reverse
print(f"\nPhase 2 reverse:")
final_r11 = (KEY + (len(test) * 0xb)) & 0xFFFF
final_r9 = ((KEY >> 8) & 0xFF) + (len(test) * 3)
final_r8 = (len(test) - 1) * 7
r11 = final_r11
r9 = final_r9 & 0xFF
r8 = final_r8

print(f"  Initial: r11=0x{r11:x}, r9=0x{r9:x}, r8={r8}")

stack = bytearray(phase2_out)
for i in range(len(test) - 1, -1, -1):
    before = stack[i]
    stack[i] = ((stack[i] >> 1) | (stack[i] << 7)) & 0xff
    after_ror = stack[i]
    stack[i] = (stack[i] - (r11 & 0xff)) & 0xff
    after_sub = stack[i]
    kdata_idx = calc_kdata_idx_magic(r9)
    shift = (r8 * 7) & 0x7
    kdata_byte = (KDATA[kdata_idx] >> shift) & 0xff
    stack[i] ^= kdata_byte
    after_xor = stack[i]
    r11 = (r11 - 0xb) & 0xFFFF
    r9 = (r9 - 3) & 0xFF
    r8 -= 7
    if i >= len(test) - 3:
        print(f"  i={i}: 0x{before:02x} -> ROR1 -> 0x{after_ror:02x} -> -0x{r11+0xb:02x} -> 0x{after_sub:02x} -> XOR kdata(0x{kdata_byte:02x}, idx={kdata_idx}) -> 0x{after_xor:02x} (r9=0x{r9+3:02x}, r8={r8+7})")

phase2_reverse = bytes(stack)
print(f"\nAfter phase 2 reverse: {phase2_reverse.hex()[:40]}...")
print(f"Phase 2 match: {phase2_reverse == phase1_out}")

if phase2_reverse != phase1_out:
    print("\n❌ Phase 2 reverse failed!")
    print(f"Expected: {phase1_out.hex()[:40]}...")
    print(f"Got:      {phase2_reverse.hex()[:40]}...")
    # Find first mismatch
    for i in range(len(test)):
        if phase1_out[i] != phase2_reverse[i]:
            print(f"First mismatch at index {i}: expected 0x{phase1_out[i]:02x}, got 0x{phase2_reverse[i]:02x}")
            break
