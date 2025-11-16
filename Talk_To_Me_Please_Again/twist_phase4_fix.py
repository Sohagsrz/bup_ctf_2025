#!/usr/bin/env python3
"""
Fix phase 4 implementation based on assembly analysis
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

# Looking at phase 4 assembly (1520-153a):
# rcx starts at 3
# rdi_limit = (length * 8) - length + 3
# Loop: rcx from 3 to rdi_limit in steps of 7
# divq %rsi -> rdx = rcx % length
# movzbl (%rsp,%rdx), %eax -> read from stack[rdx]
# movb %al, -0x1(%rbx) -> write to output[rbx-1]
# rbx increments by 1 each iteration

def twist_block_fixed(input_data, key):
    """Fixed implementation with correct phase 4"""
    data = bytearray(input_data)
    length = len(data)
    
    if length == 0:
        return bytes(data)
    
    stack = bytearray(data)
    
    # Phase 1
    r12 = key & 0xF
    r15 = key & 0xFFFF
    
    for i in range(length):
        shift = (i * 5) & 0xf
        kdata_idx = (r12 + i) % 24
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
        kdata_idx = ((r8 * 3) % 24)
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
    
    # Phase 4: Fixed based on assembly
    # rcx from 3 to (length*8 - length + 3) in steps of 7
    # rbx increments, reads from stack[rcx % length]
    output = bytearray(length)
    rbx = 0
    rcx = 3
    rdi_limit = (length * 8) - length + 3
    
    while rcx < rdi_limit and rbx < length:
        src_idx = rcx % length
        output[rbx] = stack[src_idx]
        rbx += 1
        rcx += 7
    
    # Fill remaining if needed
    if rbx < length:
        for i in range(rbx, length):
            output[i] = stack[i]
    
    return bytes(output[:length])


def reverse_twist_fixed(output_data, key):
    """Reverse with fixed phase 4"""
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
    
    # Fill remaining
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
        
        kdata_idx = ((r8 * 3) % 24)
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
        kdata_idx = (r12 + i) % 24
        kdata_val = KDATA[kdata_idx]
        kdata_byte = (kdata_val >> shift) & 0xff
        stack[i] ^= kdata_byte
        
        if i > 0:
            stack[i] ^= stack[i-1]
    
    return bytes(stack)


if __name__ == "__main__":
    print("Testing with fixed phase 4...")
    result = reverse_twist_fixed(BUCKET_ROOT, KEY)
    
    print(f"Result (hex): {result.hex()}")
    print(f"Result (ascii): {result}")
    
    if all(32 <= b < 127 for b in result):
        flag = result.decode('ascii', errors='ignore')
        print(f"\n✅ Potential flag: {flag}")
        
        encrypted = twist_block_fixed(result, KEY)
        if encrypted == BUCKET_ROOT:
            print(f"✅ VERIFIED! FLAG: {flag}")
        else:
            print(f"❌ Verification failed")
            print(f"Expected: {BUCKET_ROOT.hex()}")
            print(f"Got:      {encrypted.hex()}")
            # Show differences
            diff_positions = [i for i, (a, b) in enumerate(zip(encrypted, BUCKET_ROOT)) if a != b]
            print(f"Differences at positions: {diff_positions[:10]}")
    else:
        print("\n❌ Non-printable result")
        printable = sum(1 for b in result if 32 <= b < 127)
        print(f"Printable: {printable}/{len(result)}")
        printable_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in result)
        print(f"Printable view: {printable_str}")

