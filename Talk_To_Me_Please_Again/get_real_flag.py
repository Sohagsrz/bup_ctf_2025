#!/usr/bin/env python3
"""
Get the real flag by fixing the implementation
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
    """Magic number calculation for division by 24"""
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
    
    # Phase 1
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
    """Reverse implementation - fix the bugs"""
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
    
    # Reverse phase 3 - go backwards
    r10 = 2
    for rdi in range(length - 2, -1, -1):
        idx1 = (r10 + rdi) % length
        idx2 = rdi % length
        combined = ((stack[idx1] << 5) | (stack[idx2] >> 3)) & 0xff
        target = (rdi + 1) % length
        stack[target] ^= combined
    
    # Reverse phase 2 - go backwards
    # Calculate final values
    final_r11 = (key + (length * 0xb)) & 0xFFFF
    final_r9 = ((key >> 8) & 0xFF) + (length * 3)
    final_r8 = (length - 1) * 7
    
    r11 = final_r11
    r9 = final_r9 & 0xFF
    r8 = final_r8
    
    for i in range(length - 1, -1, -1):
        # Reverse rotate left by 1 = rotate right by 1
        stack[i] = ((stack[i] >> 1) | (stack[i] << 7)) & 0xff
        # Reverse add (subtract)
        stack[i] = (stack[i] - (r11 & 0xff)) & 0xff
        # Reverse XOR with kdata
        kdata_idx = calc_kdata_idx_magic(r9)
        shift = (r8 * 7) & 0x7
        kdata_byte = (KDATA[kdata_idx] >> shift) & 0xff
        stack[i] ^= kdata_byte
        # Update for next iteration
        r11 = (r11 - 0xb) & 0xFFFF
        r9 = (r9 - 3) & 0xFF
        r8 -= 7
    
    # Reverse phase 1 - go backwards
    # Forward order: XOR prev, XOR kdata, add key, rotate
    # Reverse order: rotate, subtract key, XOR kdata, XOR prev
    r12 = key & 0xF
    r15 = key & 0xFFFF
    for i in range(length - 1, -1, -1):
        # Reverse rotate left by 3 = rotate right by 3
        stack[i] = ((stack[i] >> 3) | (stack[i] << 5)) & 0xff
        # Reverse add (subtract)
        key_shift = (r15 >> (i & 3)) & 0xff
        stack[i] = (stack[i] - key_shift) & 0xff
        # Reverse XOR with kdata (this happens after XOR prev in forward)
        val = (r12 + i) & 0xFFFFFFFFFFFFFFFF
        kdata_idx = calc_kdata_idx_magic(val)
        shift = (i * 5) & 0xf
        kdata_byte = (KDATA[kdata_idx] >> shift) & 0xff
        stack[i] ^= kdata_byte
        # Reverse XOR with previous (this happens first in forward)
        # But we need to XOR with the ORIGINAL previous value, not the modified one
        # Since we're going backwards, stack[i-1] is already processed
        # So we need to XOR with the value before kdata was applied
        if i > 0:
            # We need the original value of stack[i-1] before phase 1 processing
            # But we don't have that... Let me think differently
            # Actually, in forward: stack[i] ^= stack[i-1] happens BEFORE kdata
            # So in reverse, we need to XOR with the value that would have been there
            # before kdata was applied. But we're going backwards, so stack[i-1] is
            # already reversed. We need to "undo" the kdata XOR on stack[i-1] first?
            # No wait, let me reconsider...
            # Forward: temp = stack[i] ^ stack[i-1]; stack[i] = temp ^ kdata
            # Reverse: temp = stack[i] ^ kdata; stack[i] = temp ^ stack[i-1]
            # But stack[i-1] in reverse is the already-reversed value
            # So we need: stack[i] = (stack[i] ^ kdata) ^ original_stack[i-1]
            # But we have reversed_stack[i-1], not original
            # Hmm, this is tricky. Let me try a different approach - process forwards but reverse operations
            pass  # Skip for now, try without this XOR
    
    return bytes(stack)

if __name__ == "__main__":
    print("Getting the real flag...")
    result = twist_reverse(BUCKET_ROOT, KEY)
    print(f"Result hex: {result.hex()}")
    print(f"Result bytes: {result}")
    
    # Try to decode
    try:
        flag = result.decode('ascii', errors='ignore')
        print(f"\nFlag (ASCII): {flag}")
        
        # Check if it's valid
        if all(32 <= b < 127 for b in result):
            print(f"\n✅ REAL FLAG: {result.decode('ascii')}")
            
            # Verify
            encrypted = twist_forward(result, KEY)
            if encrypted == BUCKET_ROOT:
                print("✅ VERIFIED!")
            else:
                print("❌ Verification failed")
                print(f"Expected: {BUCKET_ROOT.hex()}")
                print(f"Got:      {encrypted.hex()}")
        else:
            # Show printable parts
            printable = ''.join(chr(b) if 32 <= b < 127 else f'\\x{b:02x}' for b in result)
            print(f"\nPrintable view: {printable}")
            
            # Check if it starts with CS{
            if result[0] == ord('C') and result[1] == ord('S') and result[2] == ord('{'):
                print("\n✅ Starts with CS{ - extracting flag...")
                # Try to find the closing brace
                for i in range(3, len(result)):
                    if result[i] == ord('}'):
                        flag_part = result[:i+1]
                        print(f"Flag part: {flag_part}")
                        break
    except Exception as e:
        print(f"Error: {e}")

