#!/usr/bin/env python3
"""
Test forward function first, then fix reverse
"""

from clean_solve import twist_forward, twist_reverse

# Test 1: Simple input
test1 = b"A" * 29
print("Test 1: All 'A's")
enc1 = twist_forward(test1, 0x28c)
print(f"  Encrypted: {enc1.hex()[:40]}...")
dec1 = twist_reverse(enc1, 0x28c)
print(f"  Decrypted matches: {dec1 == test1}")
if dec1 != test1:
    print(f"  Expected: {test1.hex()[:40]}...")
    print(f"  Got:      {dec1.hex()[:40]}...")

# Test 2: Known pattern
test2 = b"CS{" + b"A" * 23 + b"}"
print(f"\nTest 2: CS{{A...A}}")
enc2 = twist_forward(test2, 0x28c)
print(f"  Encrypted: {enc2.hex()[:40]}...")
dec2 = twist_reverse(enc2, 0x28c)
print(f"  Decrypted matches: {dec2 == test2}")

# Test 3: Try to reverse bucket_root
print(f"\nTest 3: Reverse bucket_root")
result = twist_reverse(bytes.fromhex('8729bd38a1de74707e01a544915154cf909398dd24bec96b695fea71e2'), 0x28c)
print(f"  Result: {result.hex()}")
print(f"  ASCII: {result}")
if all(32 <= b < 127 for b in result):
    print(f"  ✅ FLAG: {result.decode('ascii')}")
else:
    print(f"  ❌ Non-printable")


