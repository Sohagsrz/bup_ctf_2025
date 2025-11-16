#!/usr/bin/env python3
"""
Complete orbit_nova implementation based on disassembly
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

def orbit_nova(input_str, length):
    """Complete orbit_nova implementation from disassembly"""
    if length == 0:
        return 0xF1EA5EED12345678
    
    # Phase 1: Forward loop
    edx = 0x9e3779b1
    r9 = 0
    r8 = 0
    rax = 0xF1EA5EED12345678
    r11 = 0xD6E8FEB86659FD93
    r10 = 0xC3A5C85C97CB3127
    
    # imulq %rsi, %rdx
    rdx = (edx * length) & 0xFFFFFFFFFFFFFFFF
    # xorq %rax, %rdx
    rdx ^= rax
    
    # Loop from 0x1840 to 0x1876
    for i in range(length):
        # movzbl (%rdi,%r8), %eax
        eax = input_str[i]
        # movq %rax, %rcx
        rcx = eax
        # addq %r9, %rax
        rax = (r9 + eax) & 0xFFFFFFFFFFFFFFFF
        # addq $0x3d, %r9
        r9 = (r9 + 0x3d) & 0xFFFFFFFFFFFFFFFF
        # imulq %r11, %rax
        rax = (rax * r11) & 0xFFFFFFFFFFFFFFFF
        # xorl %r8d, %ecx
        ecx = rcx ^ r8
        # andl $0x1f, %ecx
        ecx = ecx & 0x1f
        # xorq %rdx, %rax
        rax ^= rdx
        # rolq %cl, %rax
        rax = rol64(rax, ecx)
        # movq %rax, %rdx
        rdx = rax
        # addq %r10, %rax
        rax = (rax + r10) & 0xFFFFFFFFFFFFFFFF
        # shrq $0x1c, %rdx
        rdx_high = rdx >> 0x1c
        # addq %rax, %rdx
        rdx = (rax + rdx_high) & 0xFFFFFFFFFFFFFFFF
        # movq %r8, %rax
        rax = r8
        # addq $0x1, %r8
        r8 = (r8 + 1) & 0xFFFFFFFFFFFFFFFF
    
    # Phase 2: Backward loop
    r8 = rax  # length
    r9 = length  # pointer to end
    rbx = 0xC2B2AE3D27D4EB4D
    r11 = 0x165667B19E3779F9
    r10 = 0x4CF5AD432745937F
    
    # shlq $0x7, %r8; subq %rax, %r8
    r8 = ((r8 << 0x7) - rax) & 0xFFFFFFFFFFFFFFFF
    
    # Loop from 0x18b0 to 0x18f1
    for i in range(length):
        idx = length - 1 - i
        # movzbl -0x1(%r9), %eax
        eax = input_str[idx]
        # movq %rax, %rcx
        rcx = eax
        # xorq %r8, %rax
        rax ^= r8
        # subq $0x7f, %r8
        r8 = (r8 - 0x7f) & 0xFFFFFFFFFFFFFFFF
        # imulq %rbx, %rax
        rax = (rax * rbx) & 0xFFFFFFFFFFFFFFFF
        # xorq %rdx, %rax
        rax ^= rdx
        # movl %r9d, %edx; subq $0x1, %r9; subl %edi, %edx
        # This calculates: (r9 - rdi - 1) which is the index
        pos = idx
        # leal -0x1(%rdx,%rcx), %ecx
        ecx = ((pos + rcx - 1) & 0xFFFFFFFF) & 0x1e
        # orl $0x1, %ecx
        ecx = ecx | 0x1
        # rorq %cl, %rax
        rax = ror64(rax, ecx)
        # movq %rax, %rdx
        rdx = rax
        # shrq $0x1b, %rdx
        rdx_high = rdx >> 0x1b
        # xorq %rax, %rdx
        rdx ^= rax
        # imulq %r11, %rdx
        rdx = (rdx * r11) & 0xFFFFFFFFFFFFFFFF
        # addq %r10, %rdx
        rdx = (rdx + r10) & 0xFFFFFFFFFFFFFFFF
        # cmpq $-0x7f, %r8
        if r8 == 0xFFFFFFFFFFFFFF81:  # -0x7f
            break
    
    # Final processing
    rax = 0x27D4EB2F165667C5
    # imulq %rsi, %rax
    rax = (rax * length) & 0xFFFFFFFFFFFFFFFF
    # andl $0xf, %esi
    esi = length & 0xf
    # leal 0xd(%rsi), %ecx
    ecx = (esi + 0xd) & 0xFF
    # xorq %rdx, %rax
    rax ^= rdx
    # movq %rax, %rdx
    rdx = rax
    # rorq $0x15, %rax
    rax = ror64(rax, 0x15)
    # rolq %cl, %rdx
    rdx = rol64(rdx, ecx)
    # xorq %rdx, %rax
    rax ^= rdx
    
    return rax & 0xFFFFFFFFFFFFFFFF

# Test
if __name__ == '__main__':
    test = b"test"
    result = orbit_nova(test, len(test))
    print(f"orbit_nova('{test.decode()}') = 0x{result:016x}")
    
    FINAL_CHECK = 0xFCE62D194453D523
    print(f"Final check value: 0x{FINAL_CHECK:016x}")
    print(f"Match: {result == FINAL_CHECK}")


