#!/usr/bin/env python3
"""
Test all phases individually to find the bug
"""

from solve_correct import *

# Test with simple input
test = b"A" * 29
print("Testing forward/reverse with all phases...")
print(f"Input: {test.hex()}")

# Forward
enc = twist_forward(test, KEY)
print(f"Encrypted: {enc.hex()[:40]}...")

# Reverse
dec = twist_reverse(enc, KEY)
print(f"Decrypted: {dec.hex()[:40]}...")
print(f"Match: {dec == test}")

if dec != test:
    print("\n❌ Forward/reverse test failed!")
    print("Testing each phase individually...")
    
    # Test phase 1 only
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
    
    phase1_result = bytes(stack)
    print(f"\nPhase 1 forward: {phase1_result.hex()[:40]}...")
    
    # Reverse phase 1
    stack = bytearray(phase1_result)
    for i in range(len(test) - 1, -1, -1):
        stack[i] = ((stack[i] >> 3) | (stack[i] << 5)) & 0xff
        key_shift = (r15 >> (i & 3)) & 0xff
        stack[i] = (stack[i] - key_shift) & 0xff
        val = (r12 + i) & 0xFFFFFFFFFFFFFFFF
        kdata_idx = calc_kdata_idx_magic(val)
        shift = (i * 5) & 0xf
        kdata_byte = (KDATA[kdata_idx] >> shift) & 0xff
        stack[i] ^= kdata_byte
        if i > 0:
            stack[i] ^= stack[i-1]
    
    phase1_reverse = bytes(stack)
    print(f"Phase 1 reverse: {phase1_reverse.hex()[:40]}...")
    print(f"Phase 1 match: {phase1_reverse == test}")

# Now try to get the flag
print("\n" + "="*60)
print("Getting flag from bucket_root...")
result = twist_reverse(BUCKET_ROOT, KEY)
print(f"Result: {result.hex()}")
printable = ''.join(chr(b) if 32 <= b < 127 else f'\\x{b:02x}' for b in result)
print(f"Printable: {printable}")

# Try to see if there's a pattern
if result[0] == ord('C'):
    print("\n✅ Starts with 'C'")
    # Try to manually fix common issues
    # Maybe there's a byte offset issue?
    for offset in [1, -1, 2, -2]:
        if offset > 0:
            shifted = result[offset:] + result[:offset]
        else:
            shifted = result[offset:] + result[:offset]
        if len(shifted) == 29 and shifted[0] == ord('C') and shifted[1] == ord('S'):
            print(f"Found CS{{ with offset {offset}!")
            if all(32 <= b < 127 for b in shifted):
                print(f"Flag: {shifted.decode('ascii')}")


