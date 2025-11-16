#!/usr/bin/env python3
"""
Completely different approach: 
What if we try to understand what the program actually does
by looking at the flow, not the encryption?
"""

# Let's think about this differently:
# 1. The program reads 29 bytes
# 2. It encrypts with twist_block(input, 0x28c)
# 3. Compares with bucket_root
# 4. If match, prints success

# What if the flag is actually simpler?
# Or what if there's a way to bypass the encryption check?

# Let's try: What if we look at what happens BEFORE encryption?
# Or what if the flag format gives us constraints we can use?

BUCKET_ROOT = bytes.fromhex('8729bd38a1de74707e01a544915154cf909398dd24bec96b695fea71e2')

print("Different approach: Constraint-based solving")
print("="*60)
print("Constraints:")
print("1. Flag must be 29 bytes")
print("2. Flag format: CS{...}")
print("3. Content: 25 characters (printable ASCII)")
print("4. When encrypted with twist_block(input, 0x28c), produces bucket_root")
print()

# What if we try a completely different angle?
# Maybe the encryption is reversible in a simpler way?
# Or maybe there's a pattern in bucket_root that tells us something?

print("Analyzing bucket_root for patterns...")
print(f"Hex: {BUCKET_ROOT.hex()}")

# Check byte distribution
byte_counts = {}
for b in BUCKET_ROOT:
    byte_counts[b] = byte_counts.get(b, 0) + 1

print(f"\nMost common bytes:")
sorted_bytes = sorted(byte_counts.items(), key=lambda x: x[1], reverse=True)
for byte_val, count in sorted_bytes[:5]:
    print(f"  0x{byte_val:02x}: {count} times")

# Check if it looks like it could be a simple transformation
print("\nTrying simple transformations...")
for transform_name, transform_func in [
    ("XOR with 0xFF", lambda x: bytes(b ^ 0xFF for b in x)),
    ("XOR with 0x42", lambda x: bytes(b ^ 0x42 for b in x)),
    ("Add 1", lambda x: bytes((b + 1) & 0xFF for b in x)),
    ("Subtract 1", lambda x: bytes((b - 1) & 0xFF for b in x)),
]:
    transformed = transform_func(BUCKET_ROOT)
    printable = sum(1 for b in transformed if 32 <= b < 127)
    if printable > 20:
        print(f"  {transform_name}: {printable}/29 printable")
        ascii_view = ''.join(chr(b) if 32 <= b < 127 else '.' for b in transformed)
        if 'CS{' in ascii_view or 'cs{' in ascii_view:
            print(f"    Contains CS{{ pattern!")
            print(f"    View: {ascii_view}")

print("\n" + "="*60)
print("Alternative: Maybe the flag is in one of the buckets?")
print("Or maybe bucket_root IS the flag (encrypted)?")
print("="*60)

