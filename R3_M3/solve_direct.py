#!/usr/bin/env python3
"""
Direct approach: Complete hash implementations and try to solve
"""

import ctypes
import struct

# Constants
DRIFT_TABLE = [
    0x8a5d83122b9fc028,
    0xe90048615824641b,
    0x272bf6e58d019afd,
    0x8442a9360163fb96,
    0xe0cba1e41a4c2046
]

XOR_KEY = 0xC3B1E37F9A4D2605
FINAL_CHECK = 0xFCE62D194453D523

# Expected hashes (XORed drift_table values)
EXPECTED_HASHES = [d ^ XOR_KEY for d in DRIFT_TABLE]

def rol64(value, amount):
    """Rotate left 64-bit"""
    value = ctypes.c_uint64(value).value
    return ((value << amount) | (value >> (64 - amount))) & 0xFFFFFFFFFFFFFFFF

def ror64(value, amount):
    """Rotate right 64-bit"""
    value = ctypes.c_uint64(value).value
    return ((value >> amount) | (value << (64 - amount))) & 0xFFFFFFFFFFFFFFFF

def orbit_mist(input_str, length):
    """Full orbit_mist implementation"""
    if length == 0:
        return 0x9E3779B185EBCA87
    
    rcx = 0x9E3779B185EBCA87
    rsi = 0
    rdx = 0
    r10 = 0xC2B2AE3D27D4EB4D
    r9 = 0x165667B19E3779F9
    
    for i in range(length):
        eax = input_str[i]
        rax = (rsi + eax) & 0xFFFFFFFFFFFFFFFF
        rsi = (rsi + 0x7f) & 0xFFFFFFFFFFFFFFFF
        rax = (rax * r10) & 0xFFFFFFFFFFFFFFFF
        rax ^= rcx
        ecx = (rdx & 0x7) + 1
        rax = rol64(rax, ecx)
        rcx = rax
        rax = (rax + r9) & 0xFFFFFFFFFFFFFFFF
        rcx_high = rcx >> 0x21
        rcx = (rax + rcx_high) & 0xFFFFFFFFFFFFFFFF
        rdx += 1
    
    rax = 0xD6E8FEB86659FD93
    rdi = (length * rax) & 0xFFFFFFFFFFFFFFFF
    rdi ^= rcx
    rax = rdi
    rdi = ror64(rdi, 0x17)
    rax = rol64(rax, 0x11)
    rax ^= rdi
    return rax & 0xFFFFFFFFFFFFFFFF

def orbit_ember(input_str, length):
    """Full orbit_ember implementation"""
    if length == 0:
        r10 = 0xC3A5C85C97CB3127
        rax = 0x27D4EB2F165667C5
        rdi = 0
        rdi = (rdi * rax) & 0xFFFFFFFFFFFFFFFF
        rdi ^= r10
        rax = rdi
        rdi = ror64(rdi, 0x7)
        rax = rol64(rax, 0x5)
        rax = (rax + rdi) & 0xFFFFFFFFFFFFFFFF
        return rax & 0xFFFFFFFFFFFFFFFF
    
    r10 = 0xC3A5C85C97CB3127
    r8 = length
    rdx = 0
    r9 = 0x4CF5AD432745937F
    rsi = length - 2
    rax = 0
    
    while rdx < length:
        if rdx + 1 < length:
            eax = input_str[rsi + 1]
            r11 = rdx + 1
            rcx = eax
            if r11 < length:
                r11d = input_str[rsi]
                rcx ^= r11d
                ecx = (rcx & 0x7) + 2
                rax = (rax << 8) & 0xFFFFFFFFFFFFFFFF
                rdx += 2
                rsi -= 2
                rax |= r11d
                rax ^= r8
                r8 = (r8 + 0x13c6e) & 0xFFFFFFFFFFFFFFFF
                rax = (rax * r9) & 0xFFFFFFFFFFFFFFFF
                rax = (rax + r10) & 0xFFFFFFFFFFFFFFFF
                rax = ror64(rax, ecx)
                r10 = rax
                r10_high = r10 >> 0x1d
                r10 ^= rax
            else:
                rcx ^= 0x5a
                r11d = rcx & 0xFF
                ecx = 4
                rax = (rax << 8) & 0xFFFFFFFFFFFFFFFF
                rax |= r11d
                rax ^= r8
                r8 = (r8 + 0x13c6e) & 0xFFFFFFFFFFFFFFFF
                rax = (rax * r9) & 0xFFFFFFFFFFFFFFFF
                rax = (rax + r10) & 0xFFFFFFFFFFFFFFFF
                rax = ror64(rax, ecx)
                r10 = rax
                r10_high = r10 >> 0x1d
                r10 ^= rax
                break
        else:
            break
    
    rax = 0x27D4EB2F165667C5
    rdi = (length * rax) & 0xFFFFFFFFFFFFFFFF
    rdi ^= r10
    rax = rdi
    rdi = ror64(rdi, 0x7)
    rax = rol64(rax, 0x5)
    rax = (rax + rdi) & 0xFFFFFFFFFFFFFFFF
    return rax & 0xFFFFFFFFFFFFFFFF

# Try different function mappings
# Based on lanes analysis, let's try:
# lanes[0] = 1 -> might be orbit_ember (index 1)
# lanes[1] = 0x200000001 -> might be two functions or a different mapping
# Let's test all possible mappings

FUNCTIONS = [orbit_mist, orbit_ember]  # Start with these two

def test_inputs():
    """Test various inputs to see which hash they produce"""
    test_cases = [
        b"CS{test}",
        b"CS{flag}",
        b"CS{R3_M3}",
        b"CS{r3m3}",
        b"CS{reverse_me}",
        b"CS{something_her3}",
    ]
    
    print("=== Testing hash functions ===")
    for test in test_cases:
        print(f"\nInput: {test.decode()}")
        for i, func in enumerate(FUNCTIONS):
            try:
                hash_val = func(test, len(test))
                print(f"  {func.__name__}: 0x{hash_val:016x}")
                # Check if it matches any expected hash
                for j, expected in enumerate(EXPECTED_HASHES):
                    if hash_val == expected:
                        print(f"    *** MATCHES expected[{j}]! ***")
            except Exception as e:
                print(f"  {func.__name__}: Error - {e}")

if __name__ == '__main__':
    test_inputs()


