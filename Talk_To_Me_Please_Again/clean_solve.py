#!/usr/bin/env python3
"""
Clean solve - let's get the implementation right this time
Based on fresh radare2 analysis
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

# Phase 4 permutation for length 29
def get_phase4_permutation(length):
    """Get phase 4 permutation: rcx from 3 to (length*8-length+3) in steps of 7"""
    perm = []
    rcx = 3
    limit = (length * 8) - length + 3
    while rcx < limit and len(perm) < length:
        perm.append(rcx % length)
        rcx += 7
    return perm

PHASE4_PERM = get_phase4_permutation(29)
PHASE4_REVERSE = [0] * 29
for i, idx in enumerate(PHASE4_PERM):
    PHASE4_REVERSE[idx] = i

def twist_forward(input_data, key):
    """Forward implementation - carefully following assembly"""
    data = bytearray(input_data)
    length = len(data)
    if length == 0:
        return bytes(data)
    
    stack = bytearray(data)
    
    # Phase 1
    r12 = key & 0xF
    r15 = key & 0xFFFF
    for i in range(length):
        kdata_idx = (r12 + i) % 24
        shift = (i * 5) & 0xf
        kdata_byte = (KDATA[kdata_idx] >> shift) & 0xff
        if i > 0:
            stack[i] ^= stack[i-1]
        stack[i] ^= kdata_byte
        key_shift = (r15 >> (i & 3)) & 0xff
        stack[i] = (stack[i] + key_shift) & 0xff
        stack[i] = ((stack[i] << 3) | (stack[i] >> 5)) & 0xff
    
    # Phase 2 - r9 starts at (key >> 8) & 0xFF
    r11 = key & 0xFFFF
    r9 = (key >> 8) & 0xFF
    r8 = 0
    for i in range(length):
        kdata_idx = (r9 * 3) % 24  # Simplified
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
    
    # Phase 4 - rcx from 3 to (length*8-length+3) in steps of 7
    # rbx increments, reads from stack[rcx % length]
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
    """Reverse implementation"""
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
        kdata_idx = (r9 * 3) % 24
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
        kdata_idx = (r12 + i) % 24
        shift = (i * 5) & 0xf
        kdata_byte = (KDATA[kdata_idx] >> shift) & 0xff
        stack[i] ^= kdata_byte
        if i > 0:
            stack[i] ^= stack[i-1]
    
    return bytes(stack)

if __name__ == "__main__":
    print("Testing clean implementation...")
    result = twist_reverse(BUCKET_ROOT, KEY)
    print(f"Result: {result.hex()}")
    print(f"ASCII: {result}")
    
    if all(32 <= b < 127 for b in result):
        flag = result.decode('ascii', errors='ignore')
        print(f"\n✅ FLAG: {flag}")
        
        # Verify
        encrypted = twist_forward(result, KEY)
        if encrypted == BUCKET_ROOT:
            print("✅ VERIFIED!")
        else:
            print("❌ Verification failed")
    else:
        print("❌ Non-printable")

