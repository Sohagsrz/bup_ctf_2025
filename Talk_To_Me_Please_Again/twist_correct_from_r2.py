#!/usr/bin/env python3
"""
Correct implementation based on radare2 analysis
Key insights:
- Phase 2: r9 starts at (key >> 8) & 0xFF, increments by 3
- Phase 2: r8 starts at 0, increments by 7
- All phases confirmed from r2 output
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


def get_phase4_map(length):
    """Phase 4: rcx from 3 to (length*8 - length + 3) in steps of 7"""
    rcx = 3
    rdi_limit = (length * 8) - length + 3
    phase4_map = []
    
    while rcx < rdi_limit:
        src_idx = rcx % length
        phase4_map.append(src_idx)
        rcx += 7
        if len(phase4_map) >= length:
            break
    
    return phase4_map


def calculate_kdata_idx(val):
    """Magic number trick for modulo 24 - simplified to direct modulo"""
    # The magic number trick is used for fast division by 24
    # For our purposes, direct modulo should work
    return val % 24


def twist_block_forward(input_data, key):
    """Forward - exact from r2 analysis"""
    data = bytearray(input_data)
    length = len(data)
    
    if length == 0:
        return bytes(data)
    
    stack = bytearray(data)
    
    # Phase 1: Lines 0x13d0-0x141b
    r12 = key & 0xF
    r15 = key & 0xFFFF
    
    for i in range(length):
        # Calculate kdata index using magic number
        val = (r12 + i) & 0xFFFFFFFFFFFFFFFF
        kdata_idx = calculate_kdata_idx(val)
        shift = (i * 5) & 0xf
        
        kdata_val = KDATA[kdata_idx]
        kdata_byte = (kdata_val >> shift) & 0xff
        
        if i > 0:
            stack[i] ^= stack[i-1]
        stack[i] ^= kdata_byte
        
        key_shift = (r15 >> (i & 3)) & 0xff
        stack[i] = (stack[i] + key_shift) & 0xff
        stack[i] = ((stack[i] << 3) | (stack[i] >> 5)) & 0xff
    
    # Phase 2: Lines 0x1440-0x1484
    # r9 starts at (key >> 8) & 0xFF (from r2: movzx eax, ah)
    r11 = key & 0xFFFF
    r9 = (key >> 8) & 0xFF  # High byte!
    r8 = 0
    
    for i in range(length):
        # Calculate kdata index from r9 using magic number
        kdata_idx = calculate_kdata_idx(r9)
        shift = (r8 * 7) & 0x7
        
        kdata_val = KDATA[kdata_idx]
        kdata_byte = (kdata_val >> shift) & 0xff
        
        stack[i] ^= kdata_byte
        stack[i] = (stack[i] + (r11 & 0xff)) & 0xff
        r11 = (r11 + 0xb) & 0xFFFF
        stack[i] = ((stack[i] << 1) | (stack[i] >> 7)) & 0xff
        
        r9 = (r9 + 3) & 0xFF  # Increment by 3
        r8 += 7  # Increment by 7
    
    # Phase 3: Lines 0x14c0-0x14ed
    r10 = 2
    r8_limit = (length * 2) - 1
    
    for rdi in range(length - 1):
        idx1 = (r10 + rdi) % length
        idx2 = rdi % length
        val1 = stack[idx1]
        val2 = stack[idx2]
        combined = ((val1 << 5) | (val2 >> 3)) & 0xff
        target = (rdi + 1) % length
        stack[target] ^= combined
    
    # Phase 4: Lines 0x1520-0x153a
    phase4_map = get_phase4_map(length)
    output = bytearray(length)
    for rbx in range(len(phase4_map)):
        src_idx = phase4_map[rbx]
        output[rbx] = stack[src_idx]
    
    # Fill remaining
    if len(phase4_map) < length:
        for i in range(len(phase4_map), length):
            output[i] = stack[i]
    
    return bytes(output)


def reverse_twist_block(output_data, key):
    """Reverse all phases"""
    data = bytearray(output_data)
    length = len(data)
    
    phase4_map = get_phase4_map(length)
    
    # Reverse phase 4
    stack = bytearray(length)
    for rbx in range(len(phase4_map)):
        src_idx = phase4_map[rbx]
        stack[src_idx] = data[rbx]
    
    if len(phase4_map) < length:
        for i in range(len(phase4_map), length):
            stack[i] = data[i]
    
    # Reverse phase 3
    r10 = 2
    for rdi in range(length - 2, -1, -1):
        idx1 = (r10 + rdi) % length
        idx2 = rdi % length
        val1 = stack[idx1]
        val2 = stack[idx2]
        combined = ((val1 << 5) | (val2 >> 3)) & 0xff
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
        
        kdata_idx = calculate_kdata_idx(r9)
        shift = (r8 * 7) & 0x7
        kdata_val = KDATA[kdata_idx]
        kdata_byte = (kdata_val >> shift) & 0xff
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
        kdata_idx = calculate_kdata_idx(val)
        shift = (i * 5) & 0xf
        kdata_val = KDATA[kdata_idx]
        kdata_byte = (kdata_val >> shift) & 0xff
        stack[i] ^= kdata_byte
        
        if i > 0:
            stack[i] ^= stack[i-1]
    
    return bytes(stack)


if __name__ == "__main__":
    print("Testing with correct implementation from r2...")
    result = reverse_twist_block(BUCKET_ROOT, KEY)
    
    print(f"Result (hex): {result.hex()}")
    print(f"Result (ascii): {result}")
    
    if all(32 <= b < 127 for b in result):
        flag = result.decode('ascii', errors='ignore')
        print(f"\n✅ Potential flag: {flag}")
        
        encrypted = twist_block_forward(result, KEY)
        if encrypted == BUCKET_ROOT:
            print(f"✅✅✅ VERIFIED! FLAG: {flag}")
        else:
            print(f"❌ Verification failed")
            matches = sum(1 for a, b in zip(encrypted, BUCKET_ROOT) if a == b)
            print(f"Matches: {matches}/{len(BUCKET_ROOT)}")
    else:
        print("\n❌ Non-printable result")
        printable = sum(1 for b in result if 32 <= b < 127)
        print(f"Printable: {printable}/{len(result)}")
        printable_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in result)
        print(f"Printable view: {printable_str}")

