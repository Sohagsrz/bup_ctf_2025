#!/usr/bin/env python3
"""
Try to extract flag directly by understanding the binary structure
Maybe the flag is used as a test case or stored somewhere
"""

import struct

BUCKET_ROOT = bytes.fromhex('8729bd38a1de74707e01a544915154cf909398dd24bec96b695fea71e2')

# What if we look at the actual comparison code?
# The program compares twist_block(input, 0x28c) with bucket_root
# What if we can find test cases or intermediate values?

print("Approach: Look for the flag in the binary structure")
print("="*60)

# Check if bucket_root itself is meaningful
print("bucket_root analysis:")
print(f"  Hex: {BUCKET_ROOT.hex()}")
print(f"  Length: {len(BUCKET_ROOT)} bytes")

# What if the flag is the REVERSE of bucket_root?
# Or what if it's a simple transformation?
print("\nTrying reverse...")
reversed_bucket = BUCKET_ROOT[::-1]
printable = sum(1 for b in reversed_bucket if 32 <= b < 127)
print(f"  Reversed: {printable}/29 printable")
if printable > 20:
    ascii_view = ''.join(chr(b) if 32 <= b < 127 else '.' for b in reversed_bucket)
    print(f"  View: {ascii_view}")

# What if we need to look at the actual program flow differently?
# Maybe the flag isn't encrypted at all, just stored?
print("\n" + "="*60)
print("Maybe the approach should be:")
print("1. Find where the program stores/uses the flag")
print("2. Or find if there's a test/debug mode")
print("3. Or reverse the comparison logic to find what input works")
print("="*60)

# Actually, wait - what if we try to work backwards from bucket_root
# using a simpler assumption about the encryption?
print("\nTrying: What if encryption is simpler than we think?")
print("Maybe it's just XOR + rotation, not 4 complex phases?")

# Try simple XOR with key
for key_byte in [0x28, 0x8c, 0x28c & 0xFF, (0x28c >> 8) & 0xFF]:
    result = bytes(b ^ key_byte for b in BUCKET_ROOT)
    printable = sum(1 for b in result if 32 <= b < 127)
    if printable > 20:
        ascii_view = ''.join(chr(b) if 32 <= b < 127 else '.' for b in result)
        if 'CS{' in ascii_view or 'cs{' in ascii_view:
            print(f"  XOR with 0x{key_byte:02x}: Found CS{{ pattern!")
            print(f"    {ascii_view}")


