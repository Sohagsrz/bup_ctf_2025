#!/usr/bin/env python3
"""
Final correct implementation - checking r9 initialization carefully
From assembly:
  0x141d: movl %r11d, %eax      ; eax = r11 (key)
  0x1435: movzbl %ah, %eax      ; eax = (key >> 8) & 0xFF (high byte)
  0x143b: movq %rax, %r9        ; r9 = high byte of key
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

def twist_forward(input_data, key):
    """Forward - exact from assembly"""
    data = bytearray(input_data)
    length = len(data)
    if length == 0:
        return bytes(data)
    
    stack = bytearray(data)
    
    # Phase 1
    r12 = key & 0xF
    r15 = key & 0xFFFF
    for i in range(length):
        kdata_idx = (r12 + i) % 24
        shift = (i * 5) & 0xf
        kdata_byte = (KDATA[kdata_idx] >> shift) & 0xff
        if i > 0:
            stack[i] ^= stack[i-1]
        stack[i] ^= kdata_byte
        key_shift = (r15 >> (i & 3)) & 0xff
        stack[i] = (stack[i] + key_shift) & 0xff
        stack[i] = ((stack[i] << 3) | (stack[i] >> 5)) & 0xff
    
    # Phase 2 - r9 = (key >> 8) & 0xFF
    r11 = key & 0xFFFF
    r9 = (key >> 8) & 0xFF  # High byte: for 0x28c, this is 0x02
    r8 = 0
    
    for i in range(length):
        # kdata_idx from r9 using magic number trick
        # Simplified: (r9 * 3) % 24
        kdata_idx = (r9 * 3) % 24
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
    """Reverse - fix based on forward test"""
    # For now, return None - need working forward first
    return None

if __name__ == "__main__":
    # Test forward first
    test = b"A" * 29
    enc = twist_forward(test, KEY)
    print(f"Forward test: {enc.hex()[:40]}...")
    
    # Try reverse
    result = twist_reverse(BUCKET_ROOT, KEY)
    if result:
        print(f"Flag: {result.decode('ascii')}")


