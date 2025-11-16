#!/usr/bin/env python3
"""
Fix: r12 calculation - it's (key & 0xF) - rsp
But since we're using array indices, rsp offset might be 0
Let me check the assembly more carefully
"""

KDATA = [
    0xa3d94f21, 0x55ccaa01, 0x12345678, 0xdeadbeef,
    0x0f1e2d3c, 0xcafebabe, 0xfeedface, 0x01020304,
    0x89abcdef, 0x13579bdf, 0x2468ace0, 0x0badf00d,
    0x31415926, 0x27182818, 0xb16b00b5, 0x0c0ffee0,
    0xf00dbaaa, 0xbaadf00d, 0xabcd1234, 0x0defaced,
    0xc001d00d, 0xfeedf00d, 0xdeadc0de, 0x1337c0de
]

BUCKET_ROOT = bytes.fromhex('8729bd38a1de74707e01a544915154cf909398dd24bec96b695fea71e2')
KEY = 0x28c
MAGIC = 0xAAAAAAAAAAAAAAAB

def calc_kdata_idx_magic(val):
    """Magic number calculation"""
    val_64 = val & 0xFFFFFFFFFFFFFFFF
    product = val_64 * MAGIC
    high_bits = (product >> 64) & 0xFFFFFFFFFFFFFFFF
    shifted = high_bits >> 4
    offset = ((shifted + (shifted << 1)) << 3) & 0xFFFFFFFFFFFFFFFF
    return ((val_64 - offset) & 0xFFFFFFFFFFFFFFFF) % 24

# From assembly analysis:
# 0x13ac: and r12d, 0xf        ; r12 = (key & 0xF)
# 0x13c3: sub r12, rsp         ; r12 = r12 - rsp (stack offset)
# 0x13d0: lea rax, [r12+r8]    ; rax = r12 + r8 (where r8 is loop counter i)

# So for phase 1: val = (r12 - rsp) + i
# But since we're using array indices, rsp offset is effectively 0
# So val = (key & 0xF) + i

def twist_forward(input_data, key):
    """Forward with correct r12 calculation"""
    data = bytearray(input_data)
    length = len(data)
    if length == 0:
        return bytes(data)
    
    stack = bytearray(data)
    
    # Phase 1
    r12_base = key & 0xF  # r12 before subtracting rsp
    # r12 = r12_base - rsp, but rsp offset = 0 for our purposes
    r12 = r12_base
    r15 = key & 0xFFFF
    
    for i in range(length):
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
    
    # Phase 2
    r11 = key & 0xFFFF
    r9 = (key >> 8) & 0xFF
    r8 = 0
    for i in range(length):
        kdata_idx = calc_kdata_idx_magic(r9)
        shift = (r8 * 7) & 0x7
        kdata_byte = (KDATA[kdata_idx] >> shift) & 0xff
        stack[i] ^= kdata_byte
        stack[i] = (stack[i] + (r11 & 0xff)) & 0xff
        r11 = (r11 + 0xb) & 0xFFFF
        stack[i] = ((stack[i] << 1) | (stack[i] >> 7)) & 0xff
        r9 = (r9 + 3) & 0xFF
        r8 += 7
    
    # Phase 3
    r10 = 2
    for rdi in range(length - 1):
        idx1 = (r10 + rdi) % length
        idx2 = rdi % length
        combined = ((stack[idx1] << 5) | (stack[idx2] >> 3)) & 0xff
        target = (rdi + 1) % length
        stack[target] ^= combined
    
    # Phase 4
    output = bytearray(length)
    rbx = 0
    rcx = 3
    rdi_limit = (length * 8) - length + 3
    while rcx < rdi_limit and rbx < length:
        src_idx = rcx % length
        output[rbx] = stack[src_idx]
        rbx += 1
        rcx += 7
    
    return bytes(output)

def twist_reverse(output_data, key):
    """Reverse"""
    data = bytearray(output_data)
    length = len(data)
    
    # Reverse phase 4
    stack = bytearray(length)
    rbx = 0
    rcx = 3
    rdi_limit = (length * 8) - length + 3
    while rcx < rdi_limit and rbx < length:
        src_idx = rcx % length
        stack[src_idx] = data[rbx]
        rbx += 1
        rcx += 7
    
    # Reverse phase 3
    r10 = 2
    for rdi in range(length - 2, -1, -1):
        idx1 = (r10 + rdi) % length
        idx2 = rdi % length
        combined = ((stack[idx1] << 5) | (stack[idx2] >> 3)) & 0xff
        target = (rdi + 1) % length
        stack[target] ^= combined
    
    # Reverse phase 2
    final_r11 = (key + (length * 0xb)) & 0xFFFF
    final_r9 = ((key >> 8) & 0xFF) + (length * 3)
    final_r8 = (length - 1) * 7
    r11 = final_r11
    r9 = final_r9 & 0xFF
    r8 = final_r8
    for i in range(length - 1, -1, -1):
        stack[i] = ((stack[i] >> 1) | (stack[i] << 7)) & 0xff
        stack[i] = (stack[i] - (r11 & 0xff)) & 0xff
        kdata_idx = calc_kdata_idx_magic(r9)
        shift = (r8 * 7) & 0x7
        kdata_byte = (KDATA[kdata_idx] >> shift) & 0xff
        stack[i] ^= kdata_byte
        r11 = (r11 - 0xb) & 0xFFFF
        r9 = (r9 - 3) & 0xFF
        r8 -= 7
    
    # Reverse phase 1
    r12 = key & 0xF
    r15 = key & 0xFFFF
    for i in range(length - 1, -1, -1):
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
    
    return bytes(stack)

if __name__ == "__main__":
    # Test
    test = b"A" * 29
    enc = twist_forward(test, KEY)
    dec = twist_reverse(enc, KEY)
    print(f"Forward/reverse test: {dec == test}")
    
    # Get flag
    result = twist_reverse(BUCKET_ROOT, KEY)
    print(f"\nResult: {result.hex()}")
    if all(32 <= b < 127 for b in result):
        print(f"✅ FLAG: {result.decode('ascii')}")
        if twist_forward(result, KEY) == BUCKET_ROOT:
            print("✅ VERIFIED!")
    else:
        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in result)
        print(f"Printable: {printable}")


