#!/usr/bin/env python3
"""
Ultimate attempt - try to get the implementation exactly right
by being extremely careful with each operation
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

# Let me try to implement this one more time, but this time
# I'll be very careful about the exact operations

def mul_high64(a, b):
    """Get high 64 bits of 128-bit multiplication"""
    # For 64-bit numbers, we approximate
    # The actual assembly uses 128-bit result
    # Python's int is arbitrary precision, so we can do this
    result = a * b
    # Get high 64 bits (bits 64-127)
    return (result >> 64) & 0xFFFFFFFFFFFFFFFF


def calculate_kdata_idx_phase1(i, r12_val):
    """
    Exact calculation from assembly:
    leaq (%r12,%r8), %rax  -> val = r12 + i
    mulq %r13              -> multiply by MAGIC (128-bit result in rdx:rax)
    shrq $0x4, %rdx        -> shift high 64 bits right by 4
    leaq (%rdx,%rdx,2), %rdx -> rdx = rdx * 3
    shlq $0x3, %rdx        -> rdx = rdx * 8 (total: rdx * 24)
    subq %rdx, %rax        -> rax = rax - rdx
    """
    MAGIC = 0xAAAAAAAAAAAAAAAB
    val = (r12_val + i) & 0xFFFFFFFFFFFFFFFF
    
    # Multiply by MAGIC
    high = mul_high64(val, MAGIC)
    
    # Shift right by 4
    shifted = high >> 4
    
    # Multiply by 3, then by 8 (total: multiply by 24)
    offset = ((shifted + (shifted << 1)) << 3) & 0xFFFFFFFFFFFFFFFF
    
    # Subtract
    result = (val - offset) & 0xFFFFFFFFFFFFFFFF
    
    # The result should be modulo 24
    return result % 24


def twist_block_ultimate(input_data, key):
    """Ultimate accurate implementation"""
    data = bytearray(input_data)
    length = len(data)
    
    if length == 0:
        return bytes(data)
    
    # Copy to stack
    stack = bytearray(data)
    
    # Setup
    r12 = key & 0xF
    r15 = key & 0xFFFF
    
    # Phase 1
    for i in range(length):
        shift = (i * 5) & 0xf
        kdata_idx = calculate_kdata_idx_phase1(i, r12)
        kdata_val = KDATA[kdata_idx]
        kdata_byte = (kdata_val >> shift) & 0xff
        
        if i > 0:
            stack[i] ^= stack[i-1]
        stack[i] ^= kdata_byte
        
        key_shift = (r15 >> (i & 3)) & 0xff
        stack[i] = (stack[i] + key_shift) & 0xff
        stack[i] = ((stack[i] << 3) | (stack[i] >> 5)) & 0xff
    
    # Phase 2
    r11 = key & 0xFFFF
    r8 = 0
    
    for i in range(length):
        # Calculate index: similar to phase 1 but with r8*3
        val = r8
        kdata_idx = calculate_kdata_idx_phase1(val, 0) % 24
        
        shift = (r8 * 7) & 0x7
        kdata_val = KDATA[kdata_idx]
        kdata_byte = (kdata_val >> shift) & 0xff
        
        stack[i] ^= kdata_byte
        stack[i] = (stack[i] + (r11 & 0xff)) & 0xff
        r11 = (r11 + 0xb) & 0xFFFF
        stack[i] = ((stack[i] << 1) | (stack[i] >> 7)) & 0xff
        r8 += 7
    
    # Phase 3
    r10 = 2
    for rdi in range(length - 1):
        idx1 = (r10 + rdi) % length
        idx2 = rdi % length
        val1 = stack[idx1]
        val2 = stack[idx2]
        combined = ((val1 << 5) | (val2 >> 3)) & 0xff
        target = (rdi + 1) % length
        stack[target] ^= combined
    
    # Phase 4: Copy pattern
    output = bytearray(length)
    rbx = 0
    rcx = 3
    rdi_limit = (length * 8) - length + 3
    
    while rcx < rdi_limit and rbx < length:
        src_idx = rcx % length
        output[rbx] = stack[src_idx]
        rbx += 1
        rcx += 7
    
    if rbx < length:
        for i in range(rbx, length):
            output[i] = stack[i]
    
    return bytes(output[:length])


def reverse_twist_ultimate(output_data, key):
    """Ultimate reverse"""
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
    
    if rbx < length:
        for i in range(rbx, length):
            stack[i] = data[i]
    
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
        stack[i] = ((stack[i] >> 1) | (stack[i] << 7)) & 0xff
        stack[i] = (stack[i] - (r11 & 0xff)) & 0xff
        
        val = r8
        kdata_idx = calculate_kdata_idx_phase1(val, 0) % 24
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
        stack[i] = ((stack[i] >> 3) | (stack[i] << 5)) & 0xff
        key_shift = (r15 >> (i & 3)) & 0xff
        stack[i] = (stack[i] - key_shift) & 0xff
        
        shift = (i * 5) & 0xf
        kdata_idx = calculate_kdata_idx_phase1(i, r12)
        kdata_val = KDATA[kdata_idx]
        kdata_byte = (kdata_val >> shift) & 0xff
        stack[i] ^= kdata_byte
        
        if i > 0:
            stack[i] ^= stack[i-1]
    
    return bytes(stack)


if __name__ == "__main__":
    print("Ultimate reverse attempt...")
    result = reverse_twist_ultimate(BUCKET_ROOT, KEY)
    
    print(f"Result (hex): {result.hex()}")
    print(f"Result (ascii): {result}")
    
    if all(32 <= b < 127 for b in result):
        flag = result.decode('ascii', errors='ignore')
        print(f"\n✅ Potential flag: {flag}")
        
        encrypted = twist_block_ultimate(result, KEY)
        if encrypted == BUCKET_ROOT:
            print(f"✅ VERIFIED! FLAG: {flag}")
        else:
            print(f"❌ Verification failed")
            matches = sum(1 for a, b in zip(encrypted, BUCKET_ROOT) if a == b)
            print(f"Matches: {matches}/{len(BUCKET_ROOT)}")
    else:
        print("\n❌ Non-printable result")
        printable = sum(1 for b in result if 32 <= b < 127)
        print(f"Printable: {printable}/{len(result)}")
        
        # Try to see if it's close
        printable_str = ''.join(chr(b) if 32 <= b < 127 else f'\\x{b:02x}' for b in result)
        print(f"View: {printable_str}")

