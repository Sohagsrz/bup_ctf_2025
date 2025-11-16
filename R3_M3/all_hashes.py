#!/usr/bin/env python3
"""
Complete implementation of all hash functions
"""

import ctypes

def rol64(value, amount):
    """Rotate left 64-bit"""
    value = ctypes.c_uint64(value).value
    return ((value << amount) | (value >> (64 - amount))) & 0xFFFFFFFFFFFFFFFF

def ror64(value, amount):
    """Rotate right 64-bit"""
    value = ctypes.c_uint64(value).value
    return ((value >> amount) | (value << (64 - amount))) & 0xFFFFFFFFFFFFFFFF

def orbit_mist(input_str, length):
    """orbit_mist implementation"""
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
    """orbit_ember implementation"""
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

def orbit_tide(input_str, length):
    """orbit_tide implementation - complete from disassembly"""
    if length == 0:
        return 0x165667B19E3779F9
    
    # Phase 1: SIMD sum (simplified - actual uses SIMD instructions)
    # Process in 16-byte chunks
    sum_val = 0
    i = 0
    aligned_len = length & 0xFFFFFFF0  # Align to 16 bytes
    
    # Process aligned chunks
    while i < aligned_len:
        chunk_sum = sum(input_str[i:i+16])
        sum_val = (sum_val + chunk_sum) & 0xFFFFFFFF
        i += 16
    
    # Process remaining bytes
    while i < length:
        sum_val = (sum_val + input_str[i]) & 0xFFFFFFFF
        i += 1
    
    # Phase 2: Main loop (from 0x1580)
    r8 = 0
    rsi = 0
    r12 = 0x165667B19E3779F9
    rbx = 0x9E3779B185EBCA87
    r11 = 0xC2B2AE3D27D4EB4D
    r10 = 0x27D4EB2F165667C5
    edx = sum_val
    ebp = edx
    
    for i in range(length):
        ecx = input_str[i]
        eax = ecx
        ecx = (ecx + rsi) & 0xFFFFFFFF
        rsi += 1
        eax ^= r8
        ecx = ecx & 0x7
        r8 = (r8 + 0x1f) & 0xFFFFFFFFFFFFFFFF
        eax = (eax + ebp) & 0xFFFFFFFF
        ecx = (ecx + 3) & 0xFF
        eax = eax & 0xFF
        rax = eax
        rax = (rax * rbx) & 0xFFFFFFFFFFFFFFFF
        rax ^= r12
        rax = ror64(rax, ecx)
        rax = (rax * r11) & 0xFFFFFFFFFFFFFFFF
        r12 = (rax + r10) & 0xFFFFFFFFFFFFFFFF
    
    # Final processing
    eax = edx
    edi = length & 0x1f
    rdx = 0xC3A5C85C97CB3127
    ecx = (edi + 7) & 0xFF
    rax = (eax * rdx) & 0xFFFFFFFFFFFFFFFF
    rax ^= r12
    rdx = rax
    rax = rol64(rax, ecx)
    rdx = ror64(rdx, 0xb)
    rax ^= rdx
    
    return rax & 0xFFFFFFFFFFFFFFFF

def orbit_quartz(input_str, length):
    """orbit_quartz implementation - complete from disassembly"""
    if length == 0:
        return 0x4CF5AD432745937F
    
    # Initial setup
    rcx = (length * 0x51ED2705) & 0xFFFFFFFFFFFFFFFF
    r10 = input_str
    r11 = length
    rdi = length - 1
    r9 = 0
    r8 = 0
    rax = 0x4CF5AD432745937F
    rbx = 0xD6E8FEB86659FD93
    rsi = 0
    
    rcx ^= rax
    
    # Main loop (from 0x1660)
    while rsi < rdi:
        eax = input_str[rsi]
        r12d = input_str[rdi]
        rdx = eax
        rbp = r12d
        rax = (eax << 16) & 0xFFFFFFFFFFFFFFFF
        r12 = (r12d << 8) & 0xFFFFFFFFFFFFFFFF
        rax |= r12
        r12d = rdx
        r12d ^= rbp
        r12d = r12d & 0xFF
        r12 ^= r8
        rax |= r12
        r12 = r9
        r12 ^= rbx
        rax = (rax * r12) & 0xFFFFFFFFFFFFFFFF
        rax = (rax + rcx) & 0xFFFFFFFFFFFFFFFF
        ecx = (rdx & 0xFF) + rbp + rsi
        ecx = (ecx & 0xf) + 1
        rax = rol64(rax, ecx)
        rcx = rax
        rcx_high = rcx >> 0x20
        rcx ^= rax
        
        rsi += 1
        rdi -= 1
        r8 = (r8 + 0x83) & 0xFFFFFFFFFFFFFFFF
        r9 = (r9 + 0x9e37) & 0xFFFFFFFFFFFFFFFF
        
        if rsi >= rdi:
            break
    
    # Final processing
    rax = 0x9E3779B185EBCA87
    rax = (rax * r11) & 0xFFFFFFFFFFFFFFFF
    r11d = r11 & 0x7
    ecx = (r11d + 0xd) & 0xFF
    rax ^= rcx
    rax = ror64(rax, ecx)
    
    return rax & 0xFFFFFFFFFFFFFFFF

def orbit_haze(input_str, length):
    """orbit_haze implementation - complete from disassembly"""
    if length == 0:
        return 0xC7064742A623F8CE
    
    rcx = 0xC3B1E37F9A4D2605
    r9 = length
    rdx = 0
    r8 = length - 1
    rdi = 0
    rsi = 0
    rbx = 0xFFFFFFA3
    r11 = rcx
    r10 = 0xD6E8FEB86659FD93
    
    # Main loop (from 0x1750)
    for i in range(length):
        idx = length - 1 - i
        ebp_val = input_str[idx]
        eax = ebp_val
        ebp_val = (ebp_val + rdi) & 0xFFFFFFFF
        rdi = (rdi + 0x11) & 0xFFFFFFFF
        rdx = (rdx + ebp_val) & 0xFFFFFFFF
        eax = (eax * rbx) & 0xFFFFFFFF
        ebp_temp = rdx
        ebp_temp = ((ebp_temp << 5) - rdx) & 0xFFFFFFFF
        eax = (eax + ebp_temp) & 0xFFFFFFFF
        ebp_byte = eax & 0xFF
        eax ^= rsi
        rsi += 1
        rbp = (ebp_byte * r11) & 0xFFFFFFFFFFFFFFFF
        eax = eax & 0x7
        rbp ^= rcx
        ecx = (eax + 1) & 0xFF
        rax = rbp
        rax = rol64(rax, ecx)
        rcx = rax
        rax = (rax + r10) & 0xFFFFFFFFFFFFFFFF
        rcx_high = rcx >> 0x1e
        rcx = (rax + rcx_high) & 0xFFFFFFFFFFFFFFFF
    
    # Final processing
    rax = 0x4CF5AD432745937F
    rdx = (rdx * rax) & 0xFFFFFFFFFFFFFFFF
    rdx ^= rcx
    rax = rdx
    rdx = rol64(rdx, 0x9)
    rax = ror64(rax, 0x13)
    rax ^= rdx
    
    return rax & 0xFFFFFFFFFFFFFFFF

def orbit_nova(input_str, length):
    """Complete orbit_nova implementation"""
    if length == 0:
        return 0xF1EA5EED12345678
    
    # Phase 1: Forward loop
    edx = 0x9e3779b1
    r9 = 0
    r8 = 0
    rax = 0xF1EA5EED12345678
    r11 = 0xD6E8FEB86659FD93
    r10 = 0xC3A5C85C97CB3127
    
    rdx = (edx * length) & 0xFFFFFFFFFFFFFFFF
    rdx ^= rax
    
    for i in range(length):
        eax = input_str[i]
        rcx = eax
        rax = (r9 + eax) & 0xFFFFFFFFFFFFFFFF
        r9 = (r9 + 0x3d) & 0xFFFFFFFFFFFFFFFF
        rax = (rax * r11) & 0xFFFFFFFFFFFFFFFF
        ecx = (rcx ^ r8) & 0x1f
        rax ^= rdx
        rax = rol64(rax, ecx)
        rdx = rax
        rax = (rax + r10) & 0xFFFFFFFFFFFFFFFF
        rdx_high = rdx >> 0x1c
        rdx = (rax + rdx_high) & 0xFFFFFFFFFFFFFFFF
        rax = r8
        r8 = (r8 + 1) & 0xFFFFFFFFFFFFFFFF
    
    # Phase 2: Backward loop
    r8 = rax
    rbx = 0xC2B2AE3D27D4EB4D
    r11 = 0x165667B19E3779F9
    r10 = 0x4CF5AD432745937F
    
    r8 = ((r8 << 0x7) - rax) & 0xFFFFFFFFFFFFFFFF
    
    for i in range(length):
        idx = length - 1 - i
        eax = input_str[idx]
        rcx = eax
        rax ^= r8
        r8 = (r8 - 0x7f) & 0xFFFFFFFFFFFFFFFF
        rax = (rax * rbx) & 0xFFFFFFFFFFFFFFFF
        rax ^= rdx
        pos = idx
        ecx = ((pos + rcx - 1) & 0xFFFFFFFF) & 0x1e
        ecx = ecx | 0x1
        rax = ror64(rax, ecx)
        rdx = rax
        rdx_high = rdx >> 0x1b
        rdx ^= rax
        rdx = (rdx * r11) & 0xFFFFFFFFFFFFFFFF
        rdx = (rdx + r10) & 0xFFFFFFFFFFFFFFFF
        if r8 == 0xFFFFFFFFFFFFFF81:
            break
    
    # Final processing
    rax = 0x27D4EB2F165667C5
    rax = (rax * length) & 0xFFFFFFFFFFFFFFFF
    esi = length & 0xf
    ecx = (esi + 0xd) & 0xFF
    rax ^= rdx
    rdx = rax
    rax = ror64(rax, 0x15)
    rdx = rol64(rdx, ecx)
    rax ^= rdx
    
    return rax & 0xFFFFFFFFFFFFFFFF

# Test all functions
if __name__ == '__main__':
    test = b"test"
    print("Testing all hash functions:")
    print(f"orbit_mist: 0x{orbit_mist(test, len(test)):016x}")
    print(f"orbit_ember: 0x{orbit_ember(test, len(test)):016x}")
    print(f"orbit_tide: 0x{orbit_tide(test, len(test)):016x}")
    print(f"orbit_quartz: 0x{orbit_quartz(test, len(test)):016x}")
    print(f"orbit_haze: 0x{orbit_haze(test, len(test)):016x}")
    print(f"orbit_nova: 0x{orbit_nova(test, len(test)):016x}")

