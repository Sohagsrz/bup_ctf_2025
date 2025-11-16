#!/usr/bin/env python3
"""
Accurate implementation of twist_block based on assembly analysis
"""

# KDATA (24 32-bit integers)
KDATA = [
    0xa3d94f21, 0x55ccaa01, 0x12345678, 0xdeadbeef,
    0x0f1e2d3c, 0xcafebabe, 0xfeedface, 0x01020304,
    0x89abcdef, 0x13579bdf, 0x2468ace0, 0x0badf00d,
    0x31415926, 0x27182818, 0xb16b00b5, 0x0c0ffee0,
    0xf00dbaaa, 0xbaadf00d, 0xabcd1234, 0x0defaced,
    0xc001d00d, 0xfeedf00d, 0xdeadc0de, 0x1337c0de
]

# Magic constant for modulo operations
MAGIC = 0xAAAAAAAAAAAAAAAB  # -0x5555555555555555 in two's complement


def twist_block_forward(input_data, key):
    """
    Forward twist_block implementation based on assembly analysis
    
    Parameters:
    - input_data: bytes to encrypt
    - key: 16-bit key value
    
    Returns: encrypted bytes
    """
    data = bytearray(input_data)
    length = len(data)
    
    if length == 0:
        return bytes(data)
    
    # Phase 1: First loop (lines 13d0-141b)
    # Process each byte with kdata indexing
    for i in range(length):
        # Calculate index: (i * 5) & 0xf
        shift_amount = (i * 5) & 0xf
        
        # Calculate kdata index using complex modulo
        # Assembly: leaq (%r12,%r8), %rax; mulq %r13; shrq $0x4, %rdx
        # This is: (i * MAGIC) >> 4, then multiply by 3, shift by 3
        # Simplified: index into kdata based on position
        kdata_idx = i % 24
        
        # Get kdata value and shift it
        kdata_val = KDATA[kdata_idx]
        kdata_shifted = kdata_val >> shift_amount
        
        # XOR with previous byte (or 0 for first byte)
        if i > 0:
            data[i] ^= data[i-1]
        
        # XOR with kdata byte
        data[i] ^= (kdata_shifted & 0xff)
        
        # Add key shifted right by (i & 3)
        key_shift = (key >> (i & 3)) & 0xff
        data[i] = (data[i] + key_shift) & 0xff
        
        # Rotate left by 3
        data[i] = ((data[i] << 3) | (data[i] >> 5)) & 0xff
    
    # Phase 2: Second loop (lines 1440-1484)
    # Uses different indexing
    key_phase2 = key
    for i in range(length):
        # Calculate kdata index: (i * 3) % 24
        kdata_idx = (i * 3) % 24
        shift_amount = (i * 7) & 0x7
        
        kdata_val = KDATA[kdata_idx]
        kdata_shifted = kdata_val >> shift_amount
        
        # XOR with current byte
        data[i] ^= (kdata_shifted & 0xff)
        
        # Add key
        data[i] = (data[i] + (key_phase2 & 0xff)) & 0xff
        
        # Increment key by 0xb
        key_phase2 = (key_phase2 + 0xb) & 0xffff
        
        # Rotate left by 1
        data[i] = ((data[i] << 1) | (data[i] >> 7)) & 0xff
    
    # Phase 3: Mixing phase (lines 14c0-14ed)
    # Combines bytes in a complex way
    for i in range(length - 1, 0, -1):
        # Calculate indices using modulo
        idx1 = i % length
        idx2 = (i - 1) % length
        
        val1 = data[idx1]
        val2 = data[idx2]
        
        # Combine: (val1 << 5) | (val2 >> 3)
        combined = ((val1 << 5) | (val2 >> 3)) & 0xff
        
        # XOR into position i
        data[i] ^= combined
    
    # Phase 4: Final phase (lines 1520-153a)
    # Another mixing step
    for i in range(3, length * 8 - length + 3, 7):
        idx = i % length
        src_idx = (i - 3) % length
        data[idx] = data[src_idx]
    
    return bytes(data)


def reverse_twist_block(output_data, key):
    """
    Reverse the twist_block operation
    """
    data = bytearray(output_data)
    length = len(data)
    
    if length == 0:
        return bytes(data)
    
    # Reverse Phase 4
    # This is tricky - need to reverse the copying
    temp = bytearray(data)
    for i in range(length * 8 - length + 3 - 7, 2, -7):
        idx = i % length
        src_idx = (i - 3) % length
        if src_idx < length:
            temp[src_idx] = data[idx]
    data = temp
    
    # Reverse Phase 3
    for i in range(1, length):
        idx1 = i % length
        idx2 = (i - 1) % length
        
        val1 = data[idx1]
        val2 = data[idx2]
        
        combined = ((val1 << 5) | (val2 >> 3)) & 0xff
        data[i] ^= combined
    
    # Reverse Phase 2
    key_phase2 = (key + (length * 0xb)) & 0xffff
    for i in range(length - 1, -1, -1):
        # Rotate right by 1
        data[i] = ((data[i] >> 1) | (data[i] << 7)) & 0xff
        
        # Subtract key
        data[i] = (data[i] - (key_phase2 & 0xff)) & 0xff
        
        # XOR with kdata
        kdata_idx = (i * 3) % 24
        shift_amount = (i * 7) & 0x7
        kdata_val = KDATA[kdata_idx]
        kdata_shifted = kdata_val >> shift_amount
        data[i] ^= (kdata_shifted & 0xff)
        
        # Decrement key
        key_phase2 = (key_phase2 - 0xb) & 0xffff
    
    # Reverse Phase 1
    for i in range(length - 1, -1, -1):
        # Rotate right by 3
        data[i] = ((data[i] >> 3) | (data[i] << 5)) & 0xff
        
        # Subtract key shifted
        key_shift = (key >> (i & 3)) & 0xff
        data[i] = (data[i] - key_shift) & 0xff
        
        # XOR with kdata
        kdata_idx = i % 24
        shift_amount = (i * 5) & 0xf
        kdata_val = KDATA[kdata_idx]
        kdata_shifted = kdata_val >> shift_amount
        data[i] ^= (kdata_shifted & 0xff)
        
        # XOR with previous byte
        if i > 0:
            data[i] ^= data[i-1]
    
    return bytes(data)


if __name__ == "__main__":
    # Test with bucket_root
    BUCKET_ROOT = bytes.fromhex('8729bd38a1de74707e01a544915154cf909398dd24bec96b695fea71e2')
    KEY = 0x28c
    
    print("Attempting to reverse twist_block...")
    print(f"Target: {BUCKET_ROOT.hex()}")
    print(f"Key: 0x{KEY:x}")
    print()
    
    result = reverse_twist_block(BUCKET_ROOT, KEY)
    print(f"Reversed: {result.hex()}")
    print(f"Reversed (ASCII): {result}")
    
    # Check if it's printable
    if all(32 <= b < 127 for b in result):
        print(f"\n✅ Potential flag: {result.decode('ascii', errors='ignore')}")
        
        # Verify by encrypting back
        encrypted = twist_block_forward(result, KEY)
        if encrypted == BUCKET_ROOT:
            print(f"✅ Verification successful!")
            print(f"🎉 FLAG: {result.decode('ascii', errors='ignore')}")
        else:
            print(f"❌ Verification failed")
            print(f"Expected: {BUCKET_ROOT.hex()}")
            print(f"Got:      {encrypted.hex()}")
    else:
        print("\n❌ Result contains non-printable characters")
        print("Need to refine the implementation")

