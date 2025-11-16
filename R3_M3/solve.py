#!/usr/bin/env python3
"""
Solve the R3 M3 challenge by reversing the hash functions
"""

import struct
import ctypes

# Constants from the binary
DRIFT_TABLE = [
    0x8a5d83122b9fc028,
    0xe90048615824641b,
    0x272bf6e58d019afd,
    0x8442a9360163fb96,
    0xe0cba1e41a4c2046
]

XOR_KEY = 0xC3B1E37F9A4D2605
FINAL_CHECK = 0xFCE62D194453D523

# Function addresses (relative to base 0x1000 for PIE)
ORBIT_MIST = 0x1300
ORBIT_EMBER = 0x13b0
ORBIT_TIDE = 0x1470
ORBIT_QUARTZ = 0x1620
ORBIT_HAZE = 0x1710
ORBIT_NOVA = 0x17d0

# Lanes array - these look like indices or offsets
# Let me check what they actually are
LANES = [0x1, 0x200000001, 0x0, 0x0, 0x3050]

def orbit_mist(input_str, length):
    """Reimplement orbit_mist hash function"""
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
        ecx = rdx & 0x7
        ecx = (ecx + 1) & 0xFF
        rax = ctypes.c_uint64(rax).value
        # Rotate left by cl
        rax = ((rax << ecx) | (rax >> (64 - ecx))) & 0xFFFFFFFFFFFFFFFF
        rcx = rax
        rax = (rax + r9) & 0xFFFFFFFFFFFFFFFF
        rcx_high = rcx >> 0x21
        rcx = (rax + rcx_high) & 0xFFFFFFFFFFFFFFFF
        rdx += 1
    
    rax = 0xD6E8FEB86659FD93
    rdi = (length * rax) & 0xFFFFFFFFFFFFFFFF
    rdi ^= rcx
    rax = rdi
    rdi = ctypes.c_uint64(rdi).value
    rdi = ((rdi >> 0x17) | (rdi << (64 - 0x17))) & 0xFFFFFFFFFFFFFFFF
    rax = ctypes.c_uint64(rax).value
    rax = ((rax << 0x11) | (rax >> (64 - 0x11))) & 0xFFFFFFFFFFFFFFFF
    rax ^= rdi
    return rax & 0xFFFFFFFFFFFFFFFF

def orbit_ember(input_str, length):
    """Reimplement orbit_ember hash function"""
    if length == 0:
        return 0
    
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
                ecx = rcx & 0x7
                ecx = (ecx + 2) & 0xFF
                rax = (rax << 8) & 0xFFFFFFFFFFFFFFFF
                rdx += 2
                rsi -= 2
                rax |= r11d
                rax ^= r8
                r8 = (r8 + 0x13c6e) & 0xFFFFFFFFFFFFFFFF
                rax = (rax * r9) & 0xFFFFFFFFFFFFFFFF
                rax = (rax + r10) & 0xFFFFFFFFFFFFFFFF
                rax = ctypes.c_uint64(rax).value
                rax = ((rax >> ecx) | (rax << (64 - ecx))) & 0xFFFFFFFFFFFFFFFF
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
                rax = ctypes.c_uint64(rax).value
                rax = ((rax >> ecx) | (rax << (64 - ecx))) & 0xFFFFFFFFFFFFFFFF
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
    rdi = ctypes.c_uint64(rdi).value
    rdi = ((rdi >> 0x7) | (rdi << (64 - 0x7))) & 0xFFFFFFFFFFFFFFFF
    rax = ctypes.c_uint64(rax).value
    rax = ((rax << 0x5) | (rax >> (64 - 0x5))) & 0xFFFFFFFFFFFFFFFF
    rax = (rax + rdi) & 0xFFFFFFFFFFFFFFFF
    return rax & 0xFFFFFFFFFFFFFFFF

def orbit_nova(input_str, length):
    """Reimplement orbit_nova hash function"""
    if length == 0:
        return 0
    
    # Simplified version - need full implementation
    # This is a complex hash function
    return 0

def main():
    print("=== R3 M3 Solver ===")
    print(f"XOR Key: 0x{XOR_KEY:016x}")
    print(f"Final Check: 0x{FINAL_CHECK:016x}")
    print(f"\nDrift Table (XORed with key):")
    for i, val in enumerate(DRIFT_TABLE):
        xored = val ^ XOR_KEY
        print(f"  [{i}] = 0x{val:016x} -> 0x{xored:016x}")
    
    # Test with some inputs
    test_inputs = [
        b"test",
        b"flag",
        b"CS{",
        b"CS{test}",
    ]
    
    print("\n=== Testing hash functions ===")
    for test in test_inputs:
        print(f"\nInput: {test}")
        mist_hash = orbit_mist(test, len(test))
        print(f"  orbit_mist: 0x{mist_hash:016x}")
        ember_hash = orbit_ember(test, len(test))
        print(f"  orbit_ember: 0x{ember_hash:016x}")

if __name__ == '__main__':
    main()


