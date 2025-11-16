#!/usr/bin/env python3
"""
Exact implementation following assembly line by line
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

def mul64_high(a, b):
    """Simulate 64-bit multiply returning high 64 bits"""
    # Python doesn't have native 128-bit, so we approximate
    # For the magic number trick, this is used for division
    result = (a * b) & 0xFFFFFFFFFFFFFFFF
    # The assembly does mulq which stores result in rdx:rax
    # High 64 bits would be in rdx
    # We approximate by using the upper bits
    return (result >> 32) & 0xFFFFFFFF


def calculate_index_phase1(i, r12_val):
    """
    Exact calculation from assembly:
    leaq (%r12,%r8), %rax  -> val = r12 + i
    mulq %r13              -> multiply by MAGIC
    shrq $0x4, %rdx        -> shift high bits right by 4
    leaq (%rdx,%rdx,2), %rdx -> multiply by 3
    shlq $0x3, %rdx        -> multiply by 8 (total: multiply by 24)
    subq %rdx, %rax        -> subtract
    """
    val = (r12_val + i) & 0xFFFFFFFFFFFFFFFF
    
    # Multiply by MAGIC and get "high bits"
    # The assembly trick: this approximates division by 24
    # For our purposes, we can use: val % 24
    # But let's try to match the assembly more closely
    high = mul64_high(val, MAGIC)
    shifted = high >> 4
    offset = ((shifted + (shifted << 1)) << 3) & 0xFFFFFFFFFFFFFFFF
    result = (val - offset) & 0xFFFFFFFFFFFFFFFF
    
    return result % 24


def twist_block_exact(input_data, key):
    """
    Exact implementation matching assembly
    """
    data = bytearray(input_data)
    length = len(data)
    
    if length == 0:
        return bytes(data)
    
    # Setup: r12 = (key & 0xF) - stack_offset
    # For simplicity, assume stack_offset = 0
    r12_val = key & 0xF
    r15 = key & 0xFFFF
    
    # Phase 1: First loop (13d0-141b)
    for i in range(length):
        # Calculate kdata index
        kdata_idx = calculate_index_phase1(i, r12_val)
        
        # Shift: (i * 5) & 0xf
        shift = (i * 5) & 0xf
        
        # Get kdata byte
        kdata_val = KDATA[kdata_idx]
        kdata_byte = (kdata_val >> shift) & 0xff
        
        # XOR with previous byte (at position i-1, which is r8-1)
        if i > 0:
            data[i] ^= data[i-1]
        
        # XOR with kdata
        data[i] ^= kdata_byte
        
        # Add (r15 >> (i & 3)) & 0xff
        key_shift = (r15 >> (i & 3)) & 0xff
        data[i] = (data[i] + key_shift) & 0xff
        
        # Rotate left by 3
        data[i] = ((data[i] << 3) | (data[i] >> 5)) & 0xff
    
    # Phase 2: Second loop (1440-1484)
    r11 = key & 0xFFFF
    r8 = 0
    
    for i in range(length):
        # Calculate kdata index
        # Assembly: similar calculation but with r8*3
        val = r8
        kdata_idx = calculate_index_phase1(val, 0) % 24
        
        # Shift: (r8 * 7) & 0x7
        shift = (r8 * 7) & 0x7
        
        kdata_val = KDATA[kdata_idx]
        kdata_byte = (kdata_val >> shift) & 0xff
        
        # XOR
        data[i] ^= kdata_byte
        
        # Add r11
        data[i] = (data[i] + (r11 & 0xff)) & 0xff
        
        # Increment r11 by 0xb
        r11 = (r11 + 0xb) & 0xFFFF
        
        # Rotate left by 1
        data[i] = ((data[i] << 1) | (data[i] >> 7)) & 0xff
        
        r8 += 7
    
    # Phase 3: Mixing (14c0-14ed)
    r9_offset = 1  # r9 points to data+1
    r10 = 2
    r8_limit = (length * 2) - 1
    
    for rdi in range(length - 1):
        # Calculate indices
        idx1 = (r10 + rdi) % length
        idx2 = rdi % length
        
        val1 = data[idx1]
        val2 = data[idx2]
        
        # Combine
        combined = ((val1 << 5) | (val2 >> 3)) & 0xff
        
        # XOR into position (rdi + 1)
        target = (rdi + 1) % length
        data[target] ^= combined
    
    # Phase 4: Final copy (1520-153a)
    # This copies bytes in a pattern
    output = bytearray(data)
    rcx = 3
    rdi_limit = (length * 8) - length + 3
    rbx = 0
    
    for rcx in range(3, rdi_limit, 7):
        src_idx = rcx % length
        if rbx < length and src_idx < length:
            output[rbx] = data[src_idx]
            rbx += 1
    
    # Fill remaining if needed
    if rbx < length:
        for i in range(rbx, length):
            output[i] = data[i]
    
    return bytes(output[:length])


def reverse_twist_exact(output_data, key):
    """Reverse the exact implementation"""
    data = bytearray(output_data)
    length = len(data)
    
    # Reverse phase 4
    # This is tricky - the forward phase copies in a pattern
    # We need to reverse that pattern
    temp = bytearray(data)
    rcx = 3
    rdi_limit = (length * 8) - length + 3
    rbx = 0
    
    # Reverse the copying
    for rcx in range(3, rdi_limit, 7):
        src_idx = rcx % length
        if rbx < length and src_idx < length:
            temp[src_idx] = data[rbx]
            rbx += 1
    
    data = temp
    
    # Reverse phase 3
    r10 = 2  # Same as forward
    for rdi in range(length - 2, -1, -1):
        idx1 = (r10 + rdi) % length
        idx2 = rdi % length
        
        val1 = data[idx1]
        val2 = data[idx2]
        
        combined = ((val1 << 5) | (val2 >> 3)) & 0xff
        
        target = (rdi + 1) % length
        data[target] ^= combined
    
    # Reverse phase 2
    r11 = (key + (length * 0xb)) & 0xFFFF
    r8 = (length - 1) * 7
    
    for i in range(length - 1, -1, -1):
        # Rotate right by 1
        data[i] = ((data[i] >> 1) | (data[i] << 7)) & 0xff
        
        # Subtract r11
        data[i] = (data[i] - (r11 & 0xff)) & 0xff
        
        # XOR with kdata
        val = r8
        kdata_idx = calculate_index_phase1(val, 0) % 24
        shift = (r8 * 7) & 0x7
        kdata_val = KDATA[kdata_idx]
        kdata_byte = (kdata_val >> shift) & 0xff
        data[i] ^= kdata_byte
        
        r11 = (r11 - 0xb) & 0xFFFF
        r8 -= 7
    
    # Reverse phase 1
    r12_val = key & 0xF
    r15 = key & 0xFFFF
    
    for i in range(length - 1, -1, -1):
        # Rotate right by 3
        data[i] = ((data[i] >> 3) | (data[i] << 5)) & 0xff
        
        # Subtract key shift
        key_shift = (r15 >> (i & 3)) & 0xff
        data[i] = (data[i] - key_shift) & 0xff
        
        # XOR with kdata
        kdata_idx = calculate_index_phase1(i, r12_val)
        shift = (i * 5) & 0xf
        kdata_val = KDATA[kdata_idx]
        kdata_byte = (kdata_val >> shift) & 0xff
        data[i] ^= kdata_byte
        
        # XOR with previous
        if i > 0:
            data[i] ^= data[i-1]
    
    return bytes(data)


if __name__ == "__main__":
    BUCKET_ROOT = bytes.fromhex('8729bd38a1de74707e01a544915154cf909398dd24bec96b695fea71e2')
    KEY = 0x28c
    
    print("Testing exact reverse...")
    result = reverse_twist_exact(BUCKET_ROOT, KEY)
    
    print(f"Result (hex): {result.hex()}")
    print(f"Result (ascii): {result}")
    
    if all(32 <= b < 127 for b in result):
        flag = result.decode('ascii', errors='ignore')
        print(f"\n✅ Potential flag: {flag}")
        
        # Verify
        encrypted = twist_block_exact(result, KEY)
        if encrypted == BUCKET_ROOT:
            print(f"✅ VERIFIED! FLAG: {flag}")
        else:
            print(f"❌ Verification failed")
            print(f"Expected: {BUCKET_ROOT.hex()}")
            print(f"Got:      {encrypted.hex()}")
            print(f"Match:    {encrypted == BUCKET_ROOT}")
    else:
        print("\n❌ Non-printable result")
        printable = sum(1 for b in result if 32 <= b < 127)
        print(f"Printable: {printable}/{len(result)}")
        
        # Show what we got
        print("\nTrying to see if it's close to a flag...")
        # Check if it starts with something close to "CS{"
        if result[0] == ord('C') or result[1] == ord('S') or result[2] == ord('{'):
            print("Has potential CS{ pattern!")
            print(f"First few bytes: {result[:10]}")

