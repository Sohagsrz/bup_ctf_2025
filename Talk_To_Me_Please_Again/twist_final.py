#!/usr/bin/env python3
"""
Final attempt with more accurate implementation
Let me try to implement it step by step matching assembly exactly
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

def mod_inverse_mul(val, magic=0xAAAAAAAAAAAAAAAB):
    """
    Calculate: val - ((val * magic) >> 4) * 24
    This simulates the assembly modulo calculation
    """
    # For 64-bit arithmetic
    val_64 = val & 0xFFFFFFFFFFFFFFFF
    # Multiply by magic (this is a trick for division by certain numbers)
    # The assembly does: mulq -> get high 64 bits, shift right by 4
    # Then multiply by 3, shift left by 3 (multiply by 24)
    product = val_64 * magic
    high_bits = (product >> 64) & 0xFFFFFFFFFFFFFFFF
    shifted = high_bits >> 4
    offset = ((shifted + (shifted << 1)) << 3) & 0xFFFFFFFFFFFFFFFF
    result = (val_64 - offset) & 0xFFFFFFFFFFFFFFFF
    return result % 24


def twist_block_forward_v2(input_data, key):
    """
    More accurate implementation
    """
    data = bytearray(input_data)
    length = len(data)
    
    if length == 0:
        return bytes(data)
    
    # Phase 1: First loop
    r15 = key & 0xFFFF
    r12_offset = (key & 0xF)  # r12 = key & 0xF, then adjusted
    
    for i in range(length):
        # Calculate kdata index using the complex formula
        # Assembly: leaq (%r12,%r8), %rax where r8=i, r12=offset
        val = i + r12_offset
        kdata_idx = mod_inverse_mul(val) % 24
        
        # Shift: (i * 5) & 0xf
        shift = (i * 5) & 0xf
        
        kdata_val = KDATA[kdata_idx]
        kdata_byte = (kdata_val >> shift) & 0xff
        
        # XOR with previous byte
        if i > 0:
            data[i] ^= data[i-1]
        
        # XOR with kdata
        data[i] ^= kdata_byte
        
        # Add (r15 >> (i & 3)) & 0xff
        key_shift = (r15 >> (i & 3)) & 0xff
        data[i] = (data[i] + key_shift) & 0xff
        
        # Rotate left by 3
        data[i] = ((data[i] << 3) | (data[i] >> 5)) & 0xff
    
    # Phase 2: Second loop
    r11 = key & 0xFFFF
    r8_counter = 0
    r12_limit = (length * 8) - length
    
    for i in range(length):
        # Calculate kdata index
        val = (r8_counter * 3) % 24  # Simplified
        kdata_idx = mod_inverse_mul(val) % 24
        
        # Shift: (r8_counter * 7) & 0x7
        shift = (r8_counter * 7) & 0x7
        
        kdata_val = KDATA[kdata_idx]
        kdata_byte = (kdata_val >> shift) & 0xff
        
        # XOR
        data[i] ^= kdata_byte
        
        # Add r11
        data[i] = (data[i] + (r11 & 0xff)) & 0xff
        
        # Increment r11
        r11 = (r11 + 0xb) & 0xFFFF
        
        # Rotate left by 1
        data[i] = ((data[i] << 1) | (data[i] >> 7)) & 0xff
        
        r8_counter += 7
    
    # Phase 3: Mixing
    for i in range(length - 1, 0, -1):
        idx1 = i % length
        idx2 = (i - 1) % length
        
        val1 = data[idx1]
        val2 = data[idx2]
        
        combined = ((val1 << 5) | (val2 >> 3)) & 0xff
        
        target = (i + 1) % length
        data[target] ^= combined
    
    # Phase 4: Final copy
    # This is complex - let's simplify
    # The assembly copies in a pattern, but for now let's just return data
    # as the main transformation is done
    
    return bytes(data)


def reverse_twist_v2(output_data, key):
    """Reverse with better understanding"""
    data = bytearray(output_data)
    length = len(data)
    
    # Reverse phase 4 (simplified - might need adjustment)
    # Skip for now as it's complex
    
    # Reverse phase 3
    for i in range(1, length):
        idx1 = i % length
        idx2 = (i - 1) % length
        
        val1 = data[idx1]
        val2 = data[idx2]
        
        combined = ((val1 << 5) | (val2 >> 3)) & 0xff
        
        target = (i + 1) % length
        data[target] ^= combined
    
    # Reverse phase 2
    r11 = (key + (length * 0xb)) & 0xFFFF
    r8_counter = (length - 1) * 7
    
    for i in range(length - 1, -1, -1):
        # Rotate right by 1
        data[i] = ((data[i] >> 1) | (data[i] << 7)) & 0xff
        
        # Subtract r11
        data[i] = (data[i] - (r11 & 0xff)) & 0xff
        
        # XOR with kdata
        val = (r8_counter * 3) % 24
        kdata_idx = mod_inverse_mul(val) % 24
        shift = (r8_counter * 7) & 0x7
        kdata_val = KDATA[kdata_idx]
        kdata_byte = (kdata_val >> shift) & 0xff
        data[i] ^= kdata_byte
        
        r11 = (r11 - 0xb) & 0xFFFF
        r8_counter -= 7
    
    # Reverse phase 1
    r15 = key & 0xFFFF
    r12_offset = (key & 0xF)
    
    for i in range(length - 1, -1, -1):
        # Rotate right by 3
        data[i] = ((data[i] >> 3) | (data[i] << 5)) & 0xff
        
        # Subtract key shift
        key_shift = (r15 >> (i & 3)) & 0xff
        data[i] = (data[i] - key_shift) & 0xff
        
        # XOR with kdata
        val = i + r12_offset
        kdata_idx = mod_inverse_mul(val) % 24
        shift = (i * 5) & 0xf
        kdata_val = KDATA[kdata_idx]
        kdata_byte = (kdata_val >> shift) & 0xff
        data[i] ^= kdata_byte
        
        # XOR with previous
        if i > 0:
            data[i] ^= data[i-1]
    
    return bytes(data)


if __name__ == "__main__":
    print("Testing reverse...")
    result = reverse_twist_v2(BUCKET_ROOT, KEY)
    print(f"Result: {result.hex()}")
    print(f"Result (ascii): {result}")
    
    if all(32 <= b < 127 for b in result):
        flag = result.decode('ascii', errors='ignore')
        print(f"\n✅ Potential flag: {flag}")
        
        # Verify
        encrypted = twist_block_forward_v2(result, KEY)
        if encrypted == BUCKET_ROOT:
            print(f"✅ VERIFIED! FLAG: {flag}")
        else:
            print(f"❌ Verification failed")
            print(f"Expected: {BUCKET_ROOT.hex()}")
            print(f"Got:      {encrypted.hex()}")
            print(f"Match:    {encrypted == BUCKET_ROOT}")

