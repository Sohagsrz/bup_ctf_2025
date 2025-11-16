#!/usr/bin/env python3
"""
Final solve - properly handle phase 1 reverse
The key insight: In forward, we XOR with previous BEFORE kdata
In reverse, we need to XOR with the value that was there BEFORE kdata was applied
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

def twist_reverse_correct(output_data, key):
    """Correct reverse implementation"""
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
    
    # Reverse phase 1 - the tricky part
    # Forward: stack[i] ^= stack[i-1], then stack[i] ^= kdata, then add, then rotate
    # Reverse: rotate, subtract, XOR kdata, then XOR with original stack[i-1]
    # The problem: we need original stack[i-1], but we only have the reversed value
    # Solution: Process forwards, but apply reverse operations, storing what we need
    
    r12 = key & 0xF
    r15 = key & 0xFFFF
    
    # Step 1: Reverse rotate and subtract for all bytes
    for i in range(length):
        stack[i] = ((stack[i] >> 3) | (stack[i] << 5)) & 0xff
        key_shift = (r15 >> (i & 3)) & 0xff
        stack[i] = (stack[i] - key_shift) & 0xff
    
    # Step 2: Reverse XOR kdata and XOR with previous
    # We need to do this carefully because XOR with previous uses the value
    # BEFORE kdata was applied in forward
    for i in range(length):
        # First, reverse the kdata XOR
        val = (r12 + i) & 0xFFFFFFFFFFFFFFFF
        kdata_idx = calc_kdata_idx_magic(val)
        shift = (i * 5) & 0xf
        kdata_byte = (KDATA[kdata_idx] >> shift) & 0xff
        stack[i] ^= kdata_byte
        
        # Now, reverse the XOR with previous
        # In forward: stack[i] was XORed with stack[i-1] BEFORE kdata
        # So: original[i] -> XOR prev -> XOR kdata -> add -> rotate
        # After reversing rotate and add, we have: original[i] XOR prev XOR kdata
        # After reversing kdata XOR, we have: original[i] XOR prev
        # To get original[i], we XOR with prev
        # But prev here is stack[i-1] which has already been processed
        # We need the value of stack[i-1] BEFORE kdata was applied in forward
        # That is: stack[i-1] after we've reversed its kdata XOR
        # But we just did that! So we can use stack[i-1] directly
        if i > 0:
            stack[i] ^= stack[i-1]
    
    return bytes(stack)

if __name__ == "__main__":
    print("Solving for the real flag...")
    result = twist_reverse_correct(BUCKET_ROOT, KEY)
    print(f"Result hex: {result.hex()}")
    print(f"Result: {result}")
    
    if all(32 <= b < 127 for b in result):
        flag = result.decode('ascii')
        print(f"\n🎉 REAL FLAG: {flag}")
    else:
        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in result)
        print(f"\nResult: {printable}")
        # Check if it starts with CS{
        if len(result) >= 3 and result[0] == ord('C') and result[1] == ord('S') and result[2] == ord('{'):
            # Try to extract flag part
            for i in range(3, len(result)):
                if result[i] == ord('}'):
                    flag_part = result[:i+1]
                    print(f"\nFlag part: {flag_part}")
                    try:
                        print(f"As string: {flag_part.decode('ascii', errors='ignore')}")
                    except:
                        pass
                    break


