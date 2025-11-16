#!/usr/bin/env python3
"""Test forward function from r2 implementation"""

from twist_correct_from_r2 import twist_block_forward, reverse_twist_block

# Test with known input
test = b"A" * 29
print(f"Test input: {test}")
print(f"Length: {len(test)}")

encrypted = twist_block_forward(test, 0x28c)
print(f"Encrypted: {encrypted.hex()[:60]}...")

# Try to reverse
decrypted = reverse_twist_block(encrypted, 0x28c)
print(f"Decrypted: {decrypted}")
print(f"Match: {decrypted == test}")

if decrypted != test:
    print("Forward/reverse test failed - implementation has bugs")
    # Show differences
    for i, (a, b) in enumerate(zip(test, decrypted)):
        if a != b:
            print(f"  Position {i}: expected 0x{a:02x}, got 0x{b:02x}")


