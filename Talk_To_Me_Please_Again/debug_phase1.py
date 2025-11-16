#!/usr/bin/env python3
"""
Debug phase 1 carefully - let's trace through the assembly step by step
"""

KDATA = [
    0xa3d94f21, 0x55ccaa01, 0x12345678, 0xdeadbeef,
    0x0f1e2d3c, 0xcafebabe, 0xfeedface, 0x01020304,
    0x89abcdef, 0x13579bdf, 0x2468ace0, 0x0badf00d,
    0x31415926, 0x27182818, 0xb16b00b5, 0x0c0ffee0,
    0xf00dbaaa, 0xbaadf00d, 0xabcd1234, 0x0defaced,
    0xc001d00d, 0xfeedf00d, 0xdeadc0de, 0x1337c0de
]

KEY = 0x28c
MAGIC = 0xAAAAAAAAAAAAAAAB

def calc_kdata_idx_magic(val):
    val_64 = val & 0xFFFFFFFFFFFFFFFF
    product = val_64 * MAGIC
    high_bits = (product >> 64) & 0xFFFFFFFFFFFFFFFF
    shifted = high_bits >> 4
    offset = ((shifted + (shifted << 1)) << 3) & 0xFFFFFFFFFFFFFFFF
    return ((val_64 - offset) & 0xFFFFFFFFFFFFFFFF) % 24

# From assembly analysis:
# r12 = (key & 0xF) - rsp (but rsp offset = 0 for array)
# r15 = key & 0xFFFF
# For each i:
#   val = r12 + i (r8 in assembly, which is loop counter)
#   kdata_idx = magic_calc(val)
#   shift = (i * 5) & 0xf
#   kdata_byte = KDATA[kdata_idx] >> shift
#   if i > 0: stack[i] ^= stack[i-1]  (xorb -0x1(%r8), %al)
#   stack[i] ^= kdata_byte
#   key_shift = (r15 >> (i & 3)) & 0xff
#   stack[i] += key_shift
#   stack[i] = rol(stack[i], 3)

def phase1_forward_debug(data, key):
    """Phase 1 with detailed debugging"""
    stack = bytearray(data)
    length = len(data)
    r12 = key & 0xF
    r15 = key & 0xFFFF
    
    print(f"Phase 1 Forward:")
    print(f"  r12 = 0x{r12:x}, r15 = 0x{r15:x}")
    
    for i in range(length):
        val = (r12 + i) & 0xFFFFFFFFFFFFFFFF
        kdata_idx = calc_kdata_idx_magic(val)
        shift = (i * 5) & 0xf
        kdata_byte = (KDATA[kdata_idx] >> shift) & 0xff
        
        before = stack[i]
        
        # XOR with previous (if i > 0)
        if i > 0:
            stack[i] ^= stack[i-1]
            after_prev = stack[i]
        else:
            after_prev = stack[i]
        
        # XOR with kdata
        stack[i] ^= kdata_byte
        after_kdata = stack[i]
        
        # Add key shift
        key_shift = (r15 >> (i & 3)) & 0xff
        stack[i] = (stack[i] + key_shift) & 0xff
        after_add = stack[i]
        
        # Rotate left by 3
        stack[i] = ((stack[i] << 3) | (stack[i] >> 5)) & 0xff
        after_rol = stack[i]
        
        if i < 3:  # Debug first few
            print(f"  i={i}: 0x{before:02x} -> XOR prev -> 0x{after_prev:02x} -> XOR kdata(0x{kdata_byte:02x}) -> 0x{after_kdata:02x} -> +0x{key_shift:02x} -> 0x{after_add:02x} -> ROL3 -> 0x{after_rol:02x}")
    
    return bytes(stack)

def phase1_reverse_debug(data, key):
    """Phase 1 reverse with detailed debugging"""
    stack = bytearray(data)
    length = len(data)
    r12 = key & 0xF
    r15 = key & 0xFFFF
    
    print(f"\nPhase 1 Reverse:")
    print(f"  r12 = 0x{r12:x}, r15 = 0x{r15:x}")
    
    # Process backwards
    for i in range(length - 1, -1, -1):
        before = stack[i]
        
        # Reverse rotate (ROL3 -> ROR3)
        stack[i] = ((stack[i] >> 3) | (stack[i] << 5)) & 0xff
        after_ror = stack[i]
        
        # Reverse add (subtract)
        key_shift = (r15 >> (i & 3)) & 0xff
        stack[i] = (stack[i] - key_shift) & 0xff
        after_sub = stack[i]
        
        # Reverse XOR kdata
        val = (r12 + i) & 0xFFFFFFFFFFFFFFFF
        kdata_idx = calc_kdata_idx_magic(val)
        shift = (i * 5) & 0xf
        kdata_byte = (KDATA[kdata_idx] >> shift) & 0xff
        stack[i] ^= kdata_byte
        after_kdata = stack[i]
        
        # Reverse XOR with previous - THIS IS THE TRICKY PART
        # In forward: stack[i] ^= stack[i-1] happens BEFORE kdata
        # So: original[i] -> XOR prev -> XOR kdata -> add -> rol
        # After reversing: rol -> sub -> XOR kdata -> we have: original[i] XOR prev
        # To get original[i], we XOR with prev
        # But prev (stack[i-1]) is already reversed, so it's the original value
        if i > 0:
            stack[i] ^= stack[i-1]
            after_prev = stack[i]
        else:
            after_prev = stack[i]
        
        if i >= length - 3:  # Debug last few
            print(f"  i={i}: 0x{before:02x} -> ROR3 -> 0x{after_ror:02x} -> -0x{key_shift:02x} -> 0x{after_sub:02x} -> XOR kdata(0x{kdata_byte:02x}) -> 0x{after_kdata:02x} -> XOR prev -> 0x{after_prev:02x}")
    
    return bytes(stack)

if __name__ == "__main__":
    # Test with simple input
    test = b"A" * 10
    print(f"Test input: {test.hex()}")
    
    # Forward
    forward_result = phase1_forward_debug(test, KEY)
    print(f"\nForward result: {forward_result.hex()}")
    
    # Reverse
    reverse_result = phase1_reverse_debug(forward_result, KEY)
    print(f"\nReverse result: {reverse_result.hex()}")
    print(f"Original:       {test.hex()}")
    print(f"Match: {reverse_result == test}")


