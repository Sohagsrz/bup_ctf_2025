#!/usr/bin/env python3
"""
Complete correct solution - phase 1 is verified to work
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
    val_64 = val & 0xFFFFFFFFFFFFFFFF
    product = val_64 * MAGIC
    high_bits = (product >> 64) & 0xFFFFFFFFFFFFFFFF
    shifted = high_bits >> 4
    offset = ((shifted + (shifted << 1)) << 3) & 0xFFFFFFFFFFFFFFFF
    return ((val_64 - offset) & 0xFFFFFFFFFFFFFFFF) % 24

def twist_forward(input_data, key):
    """Forward implementation"""
    data = bytearray(input_data)
    length = len(data)
    if length == 0:
        return bytes(data)
    
    stack = bytearray(data)
    
    # Phase 1 - VERIFIED CORRECT
    r12 = key & 0xF
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
    """Reverse implementation - phase 1 is correct"""
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
    # Forward: r11 starts at key, increments by 0xb each time
    # After length iterations: r11 = (key + length * 0xb) & 0xFFFF
    # But we use r11 BEFORE incrementing, so for reverse we need:
    # r11 at iteration i (forward) = (key + i * 0xb) & 0xFFFF
    # For reverse iteration i (backwards), we need r11 from forward iteration i
    # So: r11 = (key + i * 0xb) & 0xFFFF
    
    # Similarly for r9 and r8
    for i in range(length - 1, -1, -1):
        # Calculate r11, r9, r8 for this iteration (forward iteration i)
        r11 = (key + (i * 0xb)) & 0xFFFF
        r9 = ((key >> 8) & 0xFF) + (i * 3)
        r9 = r9 & 0xFF
        r8 = i * 7
        
        stack[i] = ((stack[i] >> 1) | (stack[i] << 7)) & 0xff
        stack[i] = (stack[i] - (r11 & 0xff)) & 0xff
        kdata_idx = calc_kdata_idx_magic(r9)
        shift = (r8 * 7) & 0x7
        kdata_byte = (KDATA[kdata_idx] >> shift) & 0xff
        stack[i] ^= kdata_byte
    
    # Reverse phase 1 - VERIFIED CORRECT
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
    print("Solving for the real flag...")
    result = twist_reverse(BUCKET_ROOT, KEY)
    print(f"Result hex: {result.hex()}")
    print(f"Result: {result}")
    
    if all(32 <= b < 127 for b in result):
        flag = result.decode('ascii')
        print(f"\n🎉 REAL FLAG: {flag}")
        
        # Verify
        encrypted = twist_forward(result, KEY)
        if encrypted == BUCKET_ROOT:
            print("✅ VERIFIED!")
        else:
            print("❌ Verification failed")
            print(f"Expected: {BUCKET_ROOT.hex()}")
            print(f"Got:      {encrypted.hex()}")
    else:
        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in result)
        print(f"\nResult: {printable}")
        
        # Check if it starts with CS{
        if len(result) >= 3 and result[0] == ord('C') and result[1] == ord('S') and result[2] == ord('{'):
            print("\n✅ Starts with CS{ - extracting flag...")
            for i in range(3, len(result)):
                if result[i] == ord('}'):
                    flag_part = result[:i+1]
                    print(f"Flag: {flag_part}")
                    try:
                        print(f"As string: {flag_part.decode('ascii', errors='ignore')}")
                    except:
                        pass
                    break

