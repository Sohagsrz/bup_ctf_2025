#!/usr/bin/env python3
"""
Fix reverse phase 1 by processing forwards
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

def twist_reverse_fixed(output_data, key):
    """Reverse with fixed phase 1"""
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
    
    # Reverse phase 1 - process FORWARDS to handle XOR with previous correctly
    # Forward: stack[i] ^= stack[i-1] (before kdata)
    # So we need: after reversing kdata, XOR with original stack[i-1]
    # But we're going forwards, so stack[i-1] is already reversed
    # Solution: Store the value before kdata XOR, then use it
    
    r12 = key & 0xF
    r15 = key & 0xFFFF
    
    # First pass: reverse rotate, subtract, XOR kdata (but don't XOR prev yet)
    temp_stack = bytearray(length)
    for i in range(length):
        temp_stack[i] = stack[i]
        # Reverse rotate
        temp_stack[i] = ((temp_stack[i] >> 3) | (temp_stack[i] << 5)) & 0xff
        # Reverse subtract
        key_shift = (r15 >> (i & 3)) & 0xff
        temp_stack[i] = (temp_stack[i] - key_shift) & 0xff
        # Reverse XOR kdata
        val = (r12 + i) & 0xFFFFFFFFFFFFFFFF
        kdata_idx = calc_kdata_idx_magic(val)
        shift = (i * 5) & 0xf
        kdata_byte = (KDATA[kdata_idx] >> shift) & 0xff
        temp_stack[i] ^= kdata_byte
    
    # Second pass: XOR with previous (using values from temp_stack)
    for i in range(length):
        if i > 0:
            # Forward did: stack[i] ^= stack[i-1] BEFORE kdata
            # So reverse: after kdata, XOR with original prev
            # temp_stack[i] already has kdata reversed
            # We need to XOR with original stack[i-1], which is temp_stack[i-1] after kdata reverse
            # But wait, that's what we have! temp_stack[i-1] is the reversed value
            # Actually, we need the value BEFORE kdata was applied in forward
            # Let me think: forward does XOR prev, then XOR kdata
            # So: original[i] -> XOR prev -> XOR kdata -> add -> rotate
            # Reverse: rotate -> subtract -> XOR kdata -> XOR prev
            # After XOR kdata, we have: original[i] XOR prev[i-1]
            # To get original[i], we XOR with prev[i-1]
            # But prev[i-1] in temp_stack is already reversed (has kdata reversed)
            # We need prev[i-1] BEFORE kdata was applied
            # So we need to "redo" the kdata XOR on temp_stack[i-1]
            val_prev = (r12 + (i-1)) & 0xFFFFFFFFFFFFFFFF
            kdata_idx_prev = calc_kdata_idx_magic(val_prev)
            shift_prev = ((i-1) * 5) & 0xf
            kdata_byte_prev = (KDATA[kdata_idx_prev] >> shift_prev) & 0xff
            prev_before_kdata = temp_stack[i-1] ^ kdata_byte_prev
            temp_stack[i] ^= prev_before_kdata
        stack[i] = temp_stack[i]
    
    return bytes(stack)

if __name__ == "__main__":
    result = twist_reverse_fixed(BUCKET_ROOT, KEY)
    print(f"Result: {result.hex()}")
    print(f"ASCII: {result}")
    
    if all(32 <= b < 127 for b in result):
        print(f"\n✅ FLAG: {result.decode('ascii')}")
    else:
        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in result)
        print(f"\nPrintable: {printable}")
        if result[0] == ord('C'):
            print("Starts with 'C' - close!")


