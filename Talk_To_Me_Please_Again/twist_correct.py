#!/usr/bin/env python3
"""
Most accurate implementation yet - following assembly very carefully
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

# Looking at assembly more carefully:
# - rdi = input pointer
# - rsi = output pointer (initially points to stack)
# - rdx = length
# - rcx/ecx = key (16-bit in r15, full in r11)

def twist_block_correct(input_data, key):
    """
    Most accurate implementation based on detailed assembly analysis
    """
    data = bytearray(input_data)
    length = len(data)
    
    if length == 0:
        return bytes(data)
    
    # Copy to "stack" (we'll use a separate array)
    stack = bytearray(data)
    
    # Setup from assembly:
    # r12 = (key & 0xF) - stack_offset
    # For our case, assume stack_offset = 0, so r12 = key & 0xF
    r12 = key & 0xF
    r15 = key & 0xFFFF  # r15 = key (16-bit)
    
    # Phase 1: Loop from 13d0 to 141b
    # r8 = loop counter (starts at 0, goes to length)
    # rsi = also loop counter
    for i in range(length):
        # Calculate address: leaq (%r12,%r8), %rax
        # This is: r12 + i (where i is the loop counter)
        addr = (r12 + i) & 0xFFFFFFFFFFFFFFFF
        
        # Calculate shift: leal (%rsi,%rsi,4), %ecx; andl $0xf, %ecx
        # This is: (i * 5) & 0xf
        shift = (i * 5) & 0xf
        
        # Magic number division trick to get kdata index
        # mulq %r13 (MAGIC), shrq $0x4, %rdx
        # leaq (%rdx,%rdx,2), %rdx; shlq $0x3, %rdx; subq %rdx, %rax
        # This calculates: addr - ((addr * MAGIC) >> 4) * 24
        # Which is equivalent to: addr % 24 (for the magic number trick)
        # Let's use modulo directly for now
        kdata_idx = addr % 24
        
        # Get kdata value and shift
        kdata_val = KDATA[kdata_idx]
        kdata_byte = (kdata_val >> shift) & 0xff
        
        # XOR with previous byte: xorb -0x1(%r8), %al
        # r8 points to current position, so -1 is previous
        if i > 0:
            stack[i] ^= stack[i-1]
        
        # XOR with kdata
        stack[i] ^= kdata_byte
        
        # Add key shifted: sarl %cl, %edx; addl %edx, %eax
        # edx = r15, cl = (i & 3)
        key_shift = (r15 >> (i & 3)) & 0xff
        stack[i] = (stack[i] + key_shift) & 0xff
        
        # Rotate left by 3: rolb $0x3, %al
        stack[i] = ((stack[i] << 3) | (stack[i] >> 5)) & 0xff
    
    # Phase 2: Loop from 1440 to 1484
    r11 = key & 0xFFFF  # r11 = key
    r8 = 0  # r8 is counter, increments by 7
    r9 = (key >> 8) & 0xFF  # r9 = key high byte
    
    for i in range(length):
        # Calculate kdata index
        # Similar calculation but with r8*3
        val = (r8 * 3) % 24  # Simplified
        kdata_idx = val % 24
        
        # Shift: (r8 * 7) & 0x7
        shift = (r8 * 7) & 0x7
        
        kdata_val = KDATA[kdata_idx]
        kdata_byte = (kdata_val >> shift) & 0xff
        
        # XOR
        stack[i] ^= kdata_byte
        
        # Add r11
        stack[i] = (stack[i] + (r11 & 0xff)) & 0xff
        
        # Increment r11 by 0xb
        r11 = (r11 + 0xb) & 0xFFFF
        
        # Rotate left by 1
        stack[i] = ((stack[i] << 1) | (stack[i] >> 7)) & 0xff
        
        r8 += 7
    
    # Phase 3: Mixing from 14c0 to 14ed
    r9_ptr = 1  # Points to stack+1
    r10 = 2
    r8_limit = (length * 2) - 1
    
    for rdi in range(length - 1):
        # Calculate indices using modulo
        idx1 = (r10 + rdi) % length
        idx2 = rdi % length
        
        val1 = stack[idx1]
        val2 = stack[idx2]
        
        # Combine: (val1 << 5) | (val2 >> 3)
        combined = ((val1 << 5) | (val2 >> 3)) & 0xff
        
        # XOR into position (rdi + 1)
        target = (rdi + 1) % length
        stack[target] ^= combined
    
    # Phase 4: Final copy from 1520 to 153a
    # This copies bytes in a specific pattern
    output = bytearray(length)
    rcx = 3
    rdi_limit = (length * 8) - length + 3
    
    # The assembly copies from stack[rcx % length] to output sequentially
    for rbx in range(length):
        rcx_val = 3 + (rbx * 7)
        src_idx = rcx_val % length
        output[rbx] = stack[src_idx]
    
    return bytes(output)


def reverse_twist_correct(output_data, key):
    """Reverse the correct implementation"""
    data = bytearray(output_data)
    length = len(data)
    
    # Reverse phase 4
    stack = bytearray(length)
    for rbx in range(length):
        rcx_val = 3 + (rbx * 7)
        src_idx = rcx_val % length
        stack[src_idx] = data[rbx]
    
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
    r11 = (key + (length * 0xb)) & 0xFFFF
    r8 = (length - 1) * 7
    
    for i in range(length - 1, -1, -1):
        # Rotate right by 1
        stack[i] = ((stack[i] >> 1) | (stack[i] << 7)) & 0xff
        
        # Subtract r11
        stack[i] = (stack[i] - (r11 & 0xff)) & 0xff
        
        # XOR with kdata
        val = (r8 * 3) % 24
        kdata_idx = val % 24
        shift = (r8 * 7) & 0x7
        kdata_val = KDATA[kdata_idx]
        kdata_byte = (kdata_val >> shift) & 0xff
        stack[i] ^= kdata_byte
        
        r11 = (r11 - 0xb) & 0xFFFF
        r8 -= 7
    
    # Reverse phase 1
    r12 = key & 0xF
    r15 = key & 0xFFFF
    
    for i in range(length - 1, -1, -1):
        # Rotate right by 3
        stack[i] = ((stack[i] >> 3) | (stack[i] << 5)) & 0xff
        
        # Subtract key shift
        key_shift = (r15 >> (i & 3)) & 0xff
        stack[i] = (stack[i] - key_shift) & 0xff
        
        # XOR with kdata
        addr = (r12 + i) & 0xFFFFFFFFFFFFFFFF
        kdata_idx = addr % 24
        shift = (i * 5) & 0xf
        kdata_val = KDATA[kdata_idx]
        kdata_byte = (kdata_val >> shift) & 0xff
        stack[i] ^= kdata_byte
        
        # XOR with previous
        if i > 0:
            stack[i] ^= stack[i-1]
    
    return bytes(stack)


if __name__ == "__main__":
    print("Testing correct reverse...")
    result = reverse_twist_correct(BUCKET_ROOT, KEY)
    
    print(f"Result (hex): {result.hex()}")
    print(f"Result (ascii): {result}")
    
    if all(32 <= b < 127 for b in result):
        flag = result.decode('ascii', errors='ignore')
        print(f"\n✅ Potential flag: {flag}")
        
        # Verify
        encrypted = twist_block_correct(result, KEY)
        if encrypted == BUCKET_ROOT:
            print(f"✅ VERIFIED! FLAG: {flag}")
        else:
            print(f"❌ Verification failed")
            print(f"Expected: {BUCKET_ROOT.hex()}")
            print(f"Got:      {encrypted.hex()}")
            diff = sum(1 for a, b in zip(encrypted, BUCKET_ROOT) if a != b)
            print(f"Differences: {diff}/{len(BUCKET_ROOT)}")
    else:
        print("\n❌ Non-printable result")
        printable = sum(1 for b in result if 32 <= b < 127)
        print(f"Printable: {printable}/{len(result)}")
        
        # Show printable parts
        printable_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in result)
        print(f"Printable view: {printable_str}")

