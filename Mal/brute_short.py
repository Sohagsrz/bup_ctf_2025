#!/usr/bin/env python3
"""
Brute force shorter strings - maybe the flag is shorter
"""

def hash_string(s):
    """Hash function matching the binary"""
    hash_val = 0x1505
    for c in s:
        hash_val = ((hash_val << 5) + hash_val + ord(c)) & 0xFFFFFFFF
    return hash_val

target = 0x72d59e59
initial = 0x1505

# Try brute forcing shorter strings with CS{...} format
import itertools
import string

print("Brute forcing short flags with CS{...} format...")
print(f"Target hash: 0x{target:08x}")
print()

# Try different inner lengths
for inner_len in range(1, 8):
    print(f"Trying inner length {inner_len}...")
    count = 0
    max_tries = 1000000
    
    # Generate all possible combinations
    chars = string.ascii_letters + string.digits + "_{}-"
    
    for combo in itertools.product(chars, repeat=inner_len):
        inner = ''.join(combo)
        flag = f"CS{{{inner}}}"
        
        h = hash_string(flag)
        if h == target:
            print(f"\n[+] FOUND FLAG: {flag}")
            print(f"[+] Hash: 0x{h:08x}")
            exit(0)
        
        count += 1
        if count >= max_tries:
            print(f"  Tried {count} combinations, no match")
            break
    
    if count < max_tries:
        print(f"  Tried all {count} combinations for length {inner_len}")

print("\n[-] Not found in short strings")


