#!/usr/bin/env python3
"""
Test each phase independently to find the bug
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
test_input = bytearray([0x41] * 29)  # All 'A's

print("Testing each phase with input of all 0x41 bytes...")
print(f"Input: {test_input.hex()[:40]}...")
print()

# Phase 1 test
stack = bytearray(test_input)
r12 = KEY & 0xF
r15 = KEY & 0xFFFF

print("Phase 1:")
for i in range(min(5, len(stack))):  # Test first 5
    if i > 0:
        stack[i] ^= stack[i-1]
    shift = (i * 5) & 0xf
    kdata_idx = (r12 + i) % 24
    kdata_byte = (KDATA[kdata_idx] >> shift) & 0xff
    stack[i] ^= kdata_byte
    key_shift = (r15 >> (i & 3)) & 0xff
    stack[i] = (stack[i] + key_shift) & 0xff
    stack[i] = ((stack[i] << 3) | (stack[i] >> 5)) & 0xff
    print(f"  [{i}] = 0x{stack[i]:02x}")

print(f"After phase 1: {stack.hex()[:40]}...")
print()

# Phase 2 test  
print("Phase 2:")
r11 = KEY & 0xFFFF
r9 = (KEY >> 8) & 0xFF
r8 = 0

for i in range(min(5, len(stack))):
    kdata_idx = (r9 * 3) % 24  # Simplified
    shift = (r8 * 7) & 0x7
    kdata_byte = (KDATA[kdata_idx] >> shift) & 0xff
    stack[i] ^= kdata_byte
    stack[i] = (stack[i] + (r11 & 0xff)) & 0xff
    r11 = (r11 + 0xb) & 0xFFFF
    stack[i] = ((stack[i] << 1) | (stack[i] >> 7)) & 0xff
    r9 = (r9 + 3) & 0xFF
    r8 += 7
    print(f"  [{i}] = 0x{stack[i]:02x} (r9=0x{r9:02x}, r8={r8}, r11=0x{r11:04x})")

print(f"After phase 2: {stack.hex()[:40]}...")
print()

# Check if we're on the right track
print("If this looks reasonable, the phases might be working.")
print("The issue might be in phase 3 or 4, or in how phases combine.")

