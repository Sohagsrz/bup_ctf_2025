#!/usr/bin/env python3
"""
More detailed implementation based on careful assembly analysis
"""

KDATA = [
    0xa3d94f21, 0x55ccaa01, 0x12345678, 0xdeadbeef,
    0x0f1e2d3c, 0xcafebabe, 0xfeedface, 0x01020304,
    0x89abcdef, 0x13579bdf, 0x2468ace0, 0x0badf00d,
    0x31415926, 0x27182818, 0xb16b00b5, 0x0c0ffee0,
    0xf00dbaaa, 0xbaadf00d, 0xabcd1234, 0x0defaced,
    0xc001d00d, 0xfeedf00d, 0xdeadc0de, 0x1337c0de
]

MAGIC = 0xAAAAAAAAAAAAAAAB


def calculate_kdata_index(i, length, r12_offset=0):
    """
    Calculate kdata index based on assembly logic
    Assembly uses: leaq (%r12,%r8), %rax; mulq %r13; shrq $0x4, %rdx
    Then: leaq (%rdx,%rdx,2), %rdx; shlq $0x3, %rdx; subq %rdx, %rax
    This calculates: (i - ((i * MAGIC) >> 4) * 3 * 8) % something
    """
    # Simplified: use modulo 24 for kdata indexing
    return i % 24


def twist_block_phase1(data, key, length):
    """Phase 1: First processing loop"""
    result = bytearray(data)
    
    for i in range(length):
        # Calculate shift: (i * 5) & 0xf
        shift = (i * 5) & 0xf
        
        # Get kdata index
        kdata_idx = calculate_kdata_index(i, length)
        kdata_val = KDATA[kdata_idx]
        kdata_byte = (kdata_val >> shift) & 0xff
        
        # XOR with previous byte (if exists)
        if i > 0:
            result[i] ^= result[i-1]
        
        # XOR with kdata byte
        result[i] ^= kdata_byte
        
        # Add (key >> (i & 3)) & 0xff
        key_shift = (key >> (i & 3)) & 0xff
        result[i] = (result[i] + key_shift) & 0xff
        
        # Rotate left by 3
        result[i] = ((result[i] << 3) | (result[i] >> 5)) & 0xff
    
    return bytes(result)


def twist_block_phase2(data, key, length):
    """Phase 2: Second processing loop"""
    result = bytearray(data)
    current_key = key & 0xffff
    
    for i in range(length):
        # kdata index: (i * 3) % 24
        kdata_idx = (i * 3) % 24
        shift = (i * 7) & 0x7
        
        kdata_val = KDATA[kdata_idx]
        kdata_byte = (kdata_val >> shift) & 0xff
        
        # XOR with current byte
        result[i] ^= kdata_byte
        
        # Add current_key (low byte)
        result[i] = (result[i] + (current_key & 0xff)) & 0xff
        
        # Increment key by 0xb
        current_key = (current_key + 0xb) & 0xffff
        
        # Rotate left by 1
        result[i] = ((result[i] << 1) | (result[i] >> 7)) & 0xff
    
    return bytes(result)


def twist_block_phase3(data, length):
    """Phase 3: Mixing phase"""
    result = bytearray(data)
    
    # This phase mixes bytes using modulo operations
    # Assembly shows: divq %rsi to get modulo, then combines bytes
    for i in range(length - 1, 0, -1):
        # Calculate indices
        idx1 = i % length
        idx2 = (i - 1) % length
        
        val1 = result[idx1]
        val2 = result[idx2]
        
        # Combine: (val1 << 5) | (val2 >> 3)
        combined = ((val1 << 5) | (val2 >> 3)) & 0xff
        
        # XOR into position i+1 (wrapping)
        target_idx = (i + 1) % length
        result[target_idx] ^= combined
    
    return bytes(result)


def twist_block_phase4(data, length):
    """Phase 4: Final copying phase"""
    result = bytearray(data)
    
    # This phase copies bytes in a pattern
    # Assembly shows loop from 3 to (length*8 - length + 3) in steps of 7
    start = 3
    end = length * 8 - length + 3
    
    # Create a copy for reading
    temp = bytearray(result)
    
    for i in range(start, end, 7):
        src_idx = (i - 3) % length
        dst_idx = i % length
        
        if src_idx < length and dst_idx < length:
            result[dst_idx] = temp[src_idx]
    
    return bytes(result)


def twist_block_forward(input_data, key):
    """Complete forward twist_block"""
    data = bytearray(input_data)
    length = len(data)
    
    if length == 0:
        return bytes(data)
    
    # Apply phases in order
    data = twist_block_phase1(data, key, length)
    data = twist_block_phase2(data, key, length)
    data = twist_block_phase3(data, length)
    data = twist_block_phase4(data, length)
    
    return bytes(data)


def reverse_phase4(data, length):
    """Reverse phase 4"""
    result = bytearray(data)
    
    start = 3
    end = length * 8 - length + 3
    
    # Reverse the copying
    temp = bytearray(result)
    for i in range(end - 7, start - 1, -7):
        src_idx = (i - 3) % length
        dst_idx = i % length
        
        if src_idx < length and dst_idx < length:
            temp[src_idx] = result[dst_idx]
    
    return bytes(temp)


def reverse_phase3(data, length):
    """Reverse phase 3"""
    result = bytearray(data)
    
    for i in range(1, length):
        idx1 = i % length
        idx2 = (i - 1) % length
        
        val1 = result[idx1]
        val2 = result[idx2]
        
        combined = ((val1 << 5) | (val2 >> 3)) & 0xff
        
        target_idx = (i + 1) % length
        result[target_idx] ^= combined
    
    return bytes(result)


def reverse_phase2(data, key, length):
    """Reverse phase 2"""
    result = bytearray(data)
    
    # Calculate final key value
    current_key = (key + (length * 0xb)) & 0xffff
    
    for i in range(length - 1, -1, -1):
        # Rotate right by 1
        result[i] = ((result[i] >> 1) | (result[i] << 7)) & 0xff
        
        # Subtract key
        result[i] = (result[i] - (current_key & 0xff)) & 0xff
        
        # XOR with kdata
        kdata_idx = (i * 3) % 24
        shift = (i * 7) & 0x7
        kdata_val = KDATA[kdata_idx]
        kdata_byte = (kdata_val >> shift) & 0xff
        result[i] ^= kdata_byte
        
        # Decrement key
        current_key = (current_key - 0xb) & 0xffff
    
    return bytes(result)


def reverse_phase1(data, key, length):
    """Reverse phase 1"""
    result = bytearray(data)
    
    for i in range(length - 1, -1, -1):
        # Rotate right by 3
        result[i] = ((result[i] >> 3) | (result[i] << 5)) & 0xff
        
        # Subtract key shift
        key_shift = (key >> (i & 3)) & 0xff
        result[i] = (result[i] - key_shift) & 0xff
        
        # XOR with kdata
        kdata_idx = calculate_kdata_index(i, length)
        shift = (i * 5) & 0xf
        kdata_val = KDATA[kdata_idx]
        kdata_byte = (kdata_val >> shift) & 0xff
        result[i] ^= kdata_byte
        
        # XOR with previous byte
        if i > 0:
            result[i] ^= result[i-1]
    
    return bytes(result)


def reverse_twist_block(output_data, key):
    """Complete reverse twist_block"""
    data = bytearray(output_data)
    length = len(data)
    
    if length == 0:
        return bytes(data)
    
    # Reverse phases in reverse order
    data = reverse_phase4(data, length)
    data = reverse_phase3(data, length)
    data = reverse_phase2(data, key, length)
    data = reverse_phase1(data, key, length)
    
    return bytes(data)


if __name__ == "__main__":
    BUCKET_ROOT = bytes.fromhex('8729bd38a1de74707e01a544915154cf909398dd24bec96b695fea71e2')
    KEY = 0x28c
    
    print("Reversing twist_block...")
    result = reverse_twist_block(BUCKET_ROOT, KEY)
    
    print(f"Result (hex): {result.hex()}")
    print(f"Result (raw): {result}")
    
    # Check if printable
    if all(32 <= b < 127 for b in result):
        flag = result.decode('ascii', errors='ignore')
        print(f"\n✅ Potential flag: {flag}")
        
        # Verify
        encrypted = twist_block_forward(result, KEY)
        if encrypted == BUCKET_ROOT:
            print(f"✅ VERIFIED! FLAG: {flag}")
        else:
            print(f"❌ Verification failed")
            print(f"Expected: {BUCKET_ROOT.hex()}")
            print(f"Got:      {encrypted.hex()}")
    else:
        print("\n❌ Non-printable result")
        # Try to see if it's close to a flag
        printable_chars = sum(1 for b in result if 32 <= b < 127)
        print(f"Printable chars: {printable_chars}/{len(result)}")
        
        # Try brute forcing with constraints
        print("\nTrying brute force with constraints...")
        # The flag should start with "CS{" and end with "}"
        # Let's try to see if we can find patterns

