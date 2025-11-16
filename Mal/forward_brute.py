#!/usr/bin/env python3
"""
Forward brute force - generate strings and hash them
Focus on CS{...} format
"""

def hash_string(s):
    """Hash function matching the binary"""
    hash_val = 0x1505
    for c in s:
        hash_val = ((hash_val << 5) + hash_val + ord(c)) & 0xFFFFFFFF
    return hash_val

target = 0x72d59e59

# Try common flag patterns
common_patterns = [
    "CS{",
    "cs{",
    "FLAG{",
    "flag{",
]

# Try different character sets
import string
import itertools

print("Forward brute force with CS{...} format...")
print(f"Target: 0x{target:08x}")
print()

# Try shorter inner strings first
chars = string.ascii_letters + string.digits + "_{}-!@#$%^&*()"

for inner_len in range(1, 12):
    print(f"Trying inner length {inner_len}...")
    count = 0
    max_per_length = 5000000
    
    for combo in itertools.product(chars, repeat=inner_len):
        inner = ''.join(combo)
        flag = f"CS{{{inner}}}"
        
        h = hash_string(flag)
        if h == target:
            print(f"\n[+] FOUND FLAG: {flag}")
            print(f"[+] Hash: 0x{h:08x}")
            exit(0)
        
        count += 1
        if count % 100000 == 0:
            print(f"  Tried {count}...")
        
        if count >= max_per_length:
            print(f"  Tried {count}, moving to next length")
            break
    
    print(f"  Completed length {inner_len}, tried {count}")

print("\n[-] Not found")


