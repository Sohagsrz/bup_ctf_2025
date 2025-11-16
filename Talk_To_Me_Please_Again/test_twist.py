#!/usr/bin/env python3
"""
Test the twist function to understand it better
"""

# Let me try to understand the algorithm by testing with simple inputs
# and see if I can match any patterns

BUCKET_ROOT = bytes.fromhex('8729bd38a1de74707e01a544915154cf909398dd24bec96b695fea71e2')
KEY = 0x28c

# Try to see if there's a pattern in bucket_root
print("Analyzing bucket_root...")
print(f"Hex: {BUCKET_ROOT.hex()}")
print(f"Length: {len(BUCKET_ROOT)} bytes")
print()

# Check for patterns
print("Byte analysis:")
for i, b in enumerate(BUCKET_ROOT):
    if 32 <= b < 127:
        print(f"  [{i:2d}]: 0x{b:02x} = '{chr(b)}' (printable)")
    else:
        print(f"  [{i:2d}]: 0x{b:02x} = {b:3d} (non-printable)")

print()
print("Trying to find if bucket_root contains any readable patterns...")

# Try XOR with common values
for xor_val in [0x00, 0xFF, 0x42, 0x43, 0x53]:  # CS in hex
    result = bytes(b ^ xor_val for b in BUCKET_ROOT)
    printable = sum(1 for b in result if 32 <= b < 127)
    if printable > 10:
        print(f"\nXOR with 0x{xor_val:02x}: {printable}/{len(result)} printable")
        print(f"  Result: {result[:50]}...")

# Try to see if it's a simple transformation
print("\nChecking if it's a simple cipher...")

# The challenge name is "Talk To Me Please Again"
# Maybe the flag is related?
possible_flags = [
    b"CS{talk_to_me_please_again}",
    b"CS{Talk_To_Me_Please_Again}",
    b"CS{TalkToMePleaseAgain}",
    b"CS{talktomepleaseagain}",
    b"CS{TalkToMePleaseAgain!}",
    b"CS{talk_to_me_please}",
    b"CS{please_talk_to_me}",
    b"CS{secret_talk_code}",
    b"CS{the_secret_code}",
]

print(f"\nTrying {len(possible_flags)} possible flag patterns...")
print("(Note: Need accurate twist_block implementation to test)")

