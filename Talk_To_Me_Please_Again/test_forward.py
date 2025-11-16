#!/usr/bin/env python3
"""
Test forward function with a known input to verify it works
"""

from twist_complete_fix import twist_block_forward, reverse_twist_block

# Test with a simple 29-byte input
test_input = b"CS{test_flag_for_verif}"
print(f"Test input: {test_input}")
print(f"Length: {len(test_input)} bytes")
print()

# Encrypt
encrypted = twist_block_forward(test_input, 0x28c)
print(f"Encrypted: {encrypted.hex()}")
print()

# Try to decrypt
decrypted = reverse_twist_block(encrypted, 0x28c)
print(f"Decrypted: {decrypted}")
print(f"Match: {decrypted == test_input}")

if decrypted == test_input:
    print("✅ Forward and reverse work correctly!")
else:
    print("❌ Forward/reverse mismatch")
    print(f"Expected: {test_input}")
    print(f"Got:      {decrypted}")
    # Show differences
    for i, (a, b) in enumerate(zip(test_input, decrypted)):
        if a != b:
            print(f"  Position {i}: expected 0x{a:02x} ('{chr(a)}'), got 0x{b:02x} ('{chr(b) if 32<=b<127 else '.'}')")

