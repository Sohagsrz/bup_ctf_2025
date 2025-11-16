#!/usr/bin/env python3
"""
Test each phase separately to understand the algorithm
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

# Let's try a completely different approach
# Maybe the algorithm name "twist" gives a hint
# Or maybe it's a known cipher

# Actually, let me check if maybe the flag is actually simpler
# and the algorithm is reversible in a simpler way

# Try: what if the algorithm is mostly XOR-based and we can brute force?
# Or what if there's a pattern we're missing?

print("Trying to find patterns...")
print(f"Bucket root: {BUCKET_ROOT.hex()}")
print()

# Check if it's a simple XOR cipher
print("Testing if it's a simple transformation...")

# Try XOR with key bytes
for i in range(4):
    key_byte = (KEY >> (i * 8)) & 0xff
    result = bytes(b ^ key_byte for b in BUCKET_ROOT)
    printable = sum(1 for b in result if 32 <= b < 127)
    if printable > 15:
        print(f"XOR with key byte {i} (0x{key_byte:02x}): {printable} printable")
        print(f"  Result: {result[:30]}...")

# Try to see if there's a Caesar cipher or simple shift
print("\nTrying simple shifts...")
for shift in range(1, 10):
    result = bytes((b + shift) & 0xff for b in BUCKET_ROOT)
    printable = sum(1 for b in result if 32 <= b < 127)
    if printable > 15:
        print(f"Shift by {shift}: {printable} printable")

# Maybe the flag is in the binary itself?
print("\nChecking if flag might be embedded...")
# We already checked strings, but let's try one more thing

# Actually, let me try one more approach: what if the algorithm
# is actually simpler and I'm overcomplicating it?
# What if "twist" just means rotating bytes or something simple?

print("\nTrying byte rotation...")
for rot in [1, 2, 3, 4, 5]:
    result = BUCKET_ROOT[rot:] + BUCKET_ROOT[:rot]
    printable = sum(1 for b in result if 32 <= b < 127)
    if printable > 15:
        print(f"Rotate by {rot}: {printable} printable")
        if b"CS{" in result or b"cs{" in result:
            print(f"  FOUND FLAG PATTERN: {result}")

# Let me also check if maybe the algorithm processes in reverse
print("\nTrying reversed...")
reversed_data = BUCKET_ROOT[::-1]
printable = sum(1 for b in reversed_data if 32 <= b < 127)
print(f"Reversed: {printable} printable")

# Check if any part looks like "CS{"
for i in range(len(BUCKET_ROOT) - 3):
    chunk = BUCKET_ROOT[i:i+3]
    if chunk == b"CS{" or chunk == b"cs{":
        print(f"Found CS{{ at position {i}!")

print("\n" + "="*60)
print("Given the complexity, the best approach is:")
print("1. Set up Linux environment (Docker/VM)")
print("2. Run binary and test inputs")
print("3. Or use dynamic analysis tools")
print("="*60)

