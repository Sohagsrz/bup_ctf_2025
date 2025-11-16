#!/usr/bin/env python3
"""
Final working implementation with dynamic phase 4
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
    """Calculate phase 4 permutation map dynamically"""
    rcx = 3
    rdi_limit = (length * 8) - length + 3
    rbx = 0
    phase4_map = []
    
    while rcx < rdi_limit and rbx < length:
        src_idx = rcx % length
        phase4_map.append(src_idx)
        rbx += 1
        rcx += 7
    
    return phase4_map


def get_phase4_reverse_map(length):
    """Get reverse mapping for phase 4"""
    forward_map = get_phase4_map(length)
    reverse_map = [0] * length
    for rbx, src_idx in enumerate(forward_map):
        reverse_map[src_idx] = rbx
    return reverse_map


def calculate_kdata_idx(val, magic=MAGIC):
    """Calculate kdata index using magic number trick"""
    val_64 = val & 0xFFFFFFFFFFFFFFFF
    product = val_64 * magic
    high_bits = (product >> 64) & 0xFFFFFFFFFFFFFFFF
    shifted = high_bits >> 4
    offset = ((shifted + (shifted << 1)) << 3) & 0xFFFFFFFFFFFFFFFF
    result = (val_64 - offset) & 0xFFFFFFFFFFFFFFFF
    return result % 24


def twist_block_forward(input_data, key):
    """Forward implementation"""
    data = bytearray(input_data)
    length = len(data)
    
    if length == 0:
        return bytes(data)
    
    stack = bytearray(data)
    phase4_map = get_phase4_map(length)
    
    # Phase 1
    r12 = key & 0xF
    r15 = key & 0xFFFF
    
    for i in range(length):
        shift = (i * 5) & 0xf
        kdata_idx = (r12 + i) % 24
        kdata_val = KDATA[kdata_idx]
        kdata_byte = (kdata_val >> shift) & 0xff
        
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
        # Simplified: use modulo like phase 1
        kdata_idx = (r9 * 3) % 24
        shift = (r8 * 7) & 0x7
        
        kdata_val = KDATA[kdata_idx]
        kdata_byte = (kdata_val >> shift) & 0xff
        
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
        val1 = stack[idx1]
        val2 = stack[idx2]
        combined = ((val1 << 5) | (val2 >> 3)) & 0xff
        target = (rdi + 1) % length
        stack[target] ^= combined
    
    # Phase 4
    output = bytearray(length)
    for rbx in range(len(phase4_map)):
        src_idx = phase4_map[rbx]
        output[rbx] = stack[src_idx]
    
    # Fill remaining if needed
    if len(phase4_map) < length:
        for i in range(len(phase4_map), length):
            output[i] = stack[i]
    
    return bytes(output)


def reverse_twist_block(output_data, key):
    """Reverse implementation"""
    data = bytearray(output_data)
    length = len(data)
    
    phase4_reverse_map = get_phase4_reverse_map(length)
    
    # Reverse phase 4
    stack = bytearray(length)
    phase4_map = get_phase4_map(length)
    for rbx in range(len(phase4_map)):
        src_idx = phase4_map[rbx]
        stack[src_idx] = data[rbx]
    
    # Fill remaining if needed
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
        
        # Simplified: use modulo like phase 1
        kdata_idx = (r9 * 3) % 24
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
        
        shift = (i * 5) & 0xf
        kdata_idx = (r12 + i) % 24
        kdata_val = KDATA[kdata_idx]
        kdata_byte = (kdata_val >> shift) & 0xff
        stack[i] ^= kdata_byte
        
        if i > 0:
            stack[i] ^= stack[i-1]
    
    return bytes(stack)


if __name__ == "__main__":
    print("Testing reverse with bucket_root...")
    result = reverse_twist_block(BUCKET_ROOT, KEY)
    
    print(f"Result (hex): {result.hex()}")
    print(f"Result (ascii): {result}")
    
    if all(32 <= b < 127 for b in result):
        flag = result.decode('ascii', errors='ignore')
        print(f"\n✅ Potential flag: {flag}")
        
        encrypted = twist_block_forward(result, KEY)
        if encrypted == BUCKET_ROOT:
            print(f"✅ VERIFIED! FLAG: {flag}")
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
        
        # Check if it starts with 'C'
        if result[0] == ord('C'):
            print("\n⚠️  Starts with 'C' - might be close!")

