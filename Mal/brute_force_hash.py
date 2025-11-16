#!/usr/bin/env python3
"""
Brute force the hash with common flag patterns
"""

def hash_string(s):
    """Hash function matching the binary"""
    hash_val = 0x1505
    for c in s:
        hash_val = ((hash_val << 5) + hash_val + ord(c)) & 0xFFFFFFFF
    return hash_val

target = 0x72d59e59

# Try common flag patterns
import string
import itertools

print("Trying common flag patterns...")

# Pattern 1: CS{...}
print("Trying CS{...} patterns...")
for length in range(5, 25):
    # Try with common characters
    charset = string.ascii_letters + string.digits + "_"
    # Limit to avoid too many combinations
    if length > 15:
        # Try specific patterns
        patterns = [
            "CS{" + "A" * (length - 4) + "}",
            "CS{" + "a" * (length - 4) + "}",
            "CS{" + "0" * (length - 4) + "}",
        ]
        for pattern in patterns:
            h = hash_string(pattern)
            if h == target:
                print(f"[+] Found: {pattern}")
                exit(0)
    else:
        # Try all combinations for shorter lengths
        for combo in itertools.product(charset, repeat=length-4):
            flag = "CS{" + ''.join(combo) + "}"
            h = hash_string(flag)
            if h == target:
                print(f"[+] Found: {flag}")
                exit(0)
            if len(flag) % 1000 == 0:
                print(f"  Tried {len(flag)} length flags...")

print("Trying without CS{} wrapper...")
# Maybe it's just the inner part
for length in range(5, 20):
    charset = string.ascii_letters + string.digits + "_"
    for combo in itertools.product(charset, repeat=length):
        flag = ''.join(combo)
        h = hash_string(flag)
        if h == target:
            print(f"[+] Found: {flag}")
            exit(0)
        if hash_string(flag) % 10000 == 0:
            print(f"  Tried length {length}...")

print("[-] Not found with brute force")

