#!/usr/bin/env python3
"""
Test phase 1 to understand the exact order of operations
"""

KDATA = [
    0xa3d94f21, 0x55ccaa01, 0x12345678, 0xdeadbeef,
    0x0f1e2d3c, 0xcafebabe, 0xfeedface, 0x01020304,
    0x89abcdef, 0x13579bdf, 0x2468ace0, 0x0badf00d,
    0x31415926, 0x27182818, 0xb16b00b5, 0x0c0ffee0,
    0xf00dbaaa, 0xbaadf00d, 0xabcd1234, 0x0defaced,
    0xc001d00d, 0xfeedf00d, 0xdeadc0de, 0x1337c0de
]

length = 5  # Test with smaller length
key = 0x28c
r12 = key & 0xF
r15 = key & 0xFFFF

test_input = bytearray([0x41, 0x42, 0x43, 0x44, 0x45])  # "ABCDE"
stack = bytearray(test_input)

print("Phase 1 forward (exact order from assembly):")
print("For each i:")
print("1. XOR with previous byte (if i > 0)")
print("2. XOR with kdata byte")
print("3. Add key shift")
print("4. Rotate left by 3")
print()

for i in range(length):
    print(f"i={i}:")
    print(f"  Before: stack[{i}] = 0x{stack[i]:02x}")
    
    # Step 1: XOR with previous
    if i > 0:
        print(f"  Step 1: XOR with previous stack[{i-1}]=0x{stack[i-1]:02x}")
        stack[i] ^= stack[i-1]
        print(f"    After XOR prev: 0x{stack[i]:02x}")
    
    # Step 2: XOR with kdata
    shift = (i * 5) & 0xf
    kdata_idx = (r12 + i) % 24
    kdata_val = KDATA[kdata_idx]
    kdata_byte = (kdata_val >> shift) & 0xff
    print(f"  Step 2: XOR with kdata[{(r12+i)%24}]>>{shift} = 0x{kdata_byte:02x}")
    stack[i] ^= kdata_byte
    print(f"    After XOR kdata: 0x{stack[i]:02x}")
    
    # Step 3: Add key shift
    key_shift = (r15 >> (i & 3)) & 0xff
    print(f"  Step 3: Add key_shift = 0x{key_shift:02x}")
    stack[i] = (stack[i] + key_shift) & 0xff
    print(f"    After add: 0x{stack[i]:02x}")
    
    # Step 4: Rotate left by 3
    print(f"  Step 4: Rotate left by 3")
    stack[i] = ((stack[i] << 3) | (stack[i] >> 5)) & 0xff
    print(f"    Final: 0x{stack[i]:02x}")
    print()

print("Forward result:", [hex(b) for b in stack])

# Now reverse
print("\n" + "="*60)
print("Phase 1 reverse (opposite order):")
print("For each i from length-1 down to 0:")
print("1. Rotate right by 3")
print("2. Subtract key shift")
print("3. XOR with kdata byte")
print("4. XOR with previous byte (if i > 0)")
print()

for i in range(length - 1, -1, -1):
    print(f"i={i}:")
    print(f"  Before: stack[{i}] = 0x{stack[i]:02x}")
    
    # Step 1: Rotate right by 3
    print(f"  Step 1: Rotate right by 3")
    stack[i] = ((stack[i] >> 3) | (stack[i] << 5)) & 0xff
    print(f"    After rotate: 0x{stack[i]:02x}")
    
    # Step 2: Subtract key shift
    key_shift = (r15 >> (i & 3)) & 0xff
    print(f"  Step 2: Subtract key_shift = 0x{key_shift:02x}")
    stack[i] = (stack[i] - key_shift) & 0xff
    print(f"    After subtract: 0x{stack[i]:02x}")
    
    # Step 3: XOR with kdata
    shift = (i * 5) & 0xf
    kdata_idx = (r12 + i) % 24
    kdata_val = KDATA[kdata_idx]
    kdata_byte = (kdata_val >> shift) & 0xff
    print(f"  Step 3: XOR with kdata[{(r12+i)%24}]>>{shift} = 0x{kdata_byte:02x}")
    stack[i] ^= kdata_byte
    print(f"    After XOR kdata: 0x{stack[i]:02x}")
    
    # Step 4: XOR with previous
    if i > 0:
        print(f"  Step 4: XOR with previous stack[{i-1}]=0x{stack[i-1]:02x}")
        stack[i] ^= stack[i-1]
        print(f"    After XOR prev: 0x{stack[i]:02x}")
    print()

print("Reverse result:", [hex(b) for b in stack])
print("Original:", [hex(b) for b in test_input])
print("Match:", stack == test_input)

