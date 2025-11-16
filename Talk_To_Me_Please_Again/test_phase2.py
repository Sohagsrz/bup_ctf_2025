#!/usr/bin/env python3
"""
Test phase 2 to understand the exact operations
"""

KDATA = [
    0xa3d94f21, 0x55ccaa01, 0x12345678, 0xdeadbeef,
    0x0f1e2d3c, 0xcafebabe, 0xfeedface, 0x01020304,
    0x89abcdef, 0x13579bdf, 0x2468ace0, 0x0badf00d,
    0x31415926, 0x27182818, 0xb16b00b5, 0x0c0ffee0,
    0xf00dbaaa, 0xbaadf00d, 0xabcd1234, 0x0defaced,
    0xc001d00d, 0xfeedf00d, 0xdeadc0de, 0x1337c0de
]

length = 5
key = 0x28c
r11 = key & 0xFFFF
r8 = 0

test_input = bytearray([0x41, 0x42, 0x43, 0x44, 0x45])
stack = bytearray(test_input)

print("Phase 2 forward:")
print("For each i:")
print("1. Calculate kdata index from r8")
print("2. XOR with kdata byte")
print("3. Add r11 (low byte)")
print("4. Increment r11 by 0xb")
print("5. Rotate left by 1")
print("6. Increment r8 by 7")
print()

for i in range(length):
    print(f"i={i}, r8={r8}, r11=0x{r11:04x}:")
    print(f"  Before: stack[{i}] = 0x{stack[i]:02x}")
    
    # Calculate kdata index - need to use the same magic number trick
    # For now, let's use simplified: (r8 * 3) % 24
    kdata_idx = ((r8 * 3) % 24)
    shift = (r8 * 7) & 0x7
    kdata_val = KDATA[kdata_idx]
    kdata_byte = (kdata_val >> shift) & 0xff
    print(f"  kdata_idx = ({r8} * 3) % 24 = {kdata_idx}, shift={shift}, kdata_byte=0x{kdata_byte:02x}")
    
    # Step 1: XOR with kdata
    stack[i] ^= kdata_byte
    print(f"  After XOR kdata: 0x{stack[i]:02x}")
    
    # Step 2: Add r11
    stack[i] = (stack[i] + (r11 & 0xff)) & 0xff
    print(f"  After add r11: 0x{stack[i]:02x}")
    
    # Step 3: Increment r11
    r11 = (r11 + 0xb) & 0xFFFF
    print(f"  r11 now: 0x{r11:04x}")
    
    # Step 4: Rotate left by 1
    stack[i] = ((stack[i] << 1) | (stack[i] >> 7)) & 0xff
    print(f"  After rotate: 0x{stack[i]:02x}")
    
    # Step 5: Increment r8
    r8 += 7
    print()

print("Forward result:", [hex(b) for b in stack])

# Now reverse
print("\n" + "="*60)
print("Phase 2 reverse:")
print("For each i from length-1 down to 0:")
print("1. Rotate right by 1")
print("2. Subtract r11")
print("3. XOR with kdata")
print("4. Decrement r11 by 0xb")
print("5. Decrement r8 by 7")
print()

# Calculate final r11 and r8 values
final_r11 = (key + (length * 0xb)) & 0xFFFF
final_r8 = (length - 1) * 7
r11 = final_r11
r8 = final_r8

for i in range(length - 1, -1, -1):
    print(f"i={i}, r8={r8}, r11=0x{r11:04x}:")
    print(f"  Before: stack[{i}] = 0x{stack[i]:02x}")
    
    # Step 1: Rotate right by 1
    stack[i] = ((stack[i] >> 1) | (stack[i] << 7)) & 0xff
    print(f"  After rotate: 0x{stack[i]:02x}")
    
    # Step 2: Subtract r11
    stack[i] = (stack[i] - (r11 & 0xff)) & 0xff
    print(f"  After subtract r11: 0x{stack[i]:02x}")
    
    # Step 3: XOR with kdata
    kdata_idx = ((r8 * 3) % 24)
    shift = (r8 * 7) & 0x7
    kdata_val = KDATA[kdata_idx]
    kdata_byte = (kdata_val >> shift) & 0xff
    print(f"  kdata_idx = ({r8} * 3) % 24 = {kdata_idx}, shift={shift}, kdata_byte=0x{kdata_byte:02x}")
    stack[i] ^= kdata_byte
    print(f"  After XOR kdata: 0x{stack[i]:02x}")
    
    # Step 4: Decrement r11
    r11 = (r11 - 0xb) & 0xFFFF
    print(f"  r11 now: 0x{r11:04x}")
    
    # Step 5: Decrement r8
    r8 -= 7
    print()

print("Reverse result:", [hex(b) for b in stack])
print("Original:", [hex(b) for b in test_input])
print("Match:", stack == test_input)

