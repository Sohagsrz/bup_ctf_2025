#!/usr/bin/env python3
"""
Correctly reverse the hash algorithm.
Hash: hash = (hash * 33 + char) mod 2^32, starting from 0x1505
Target: 0x72d59e59

Working backwards:
If hash = (prev_hash * 33 + char) mod 2^32
Then: prev_hash * 33 = (hash - char) mod 2^32
We need: (hash - char) mod 2^32 ≡ 0 (mod 33)
So: hash mod 33 = char mod 33
"""

def hash_string(s):
    """Hash function matching the binary"""
    hash_val = 0x1505
    for c in s:
        hash_val = ((hash_val << 5) + hash_val + ord(c)) & 0xFFFFFFFF
    return hash_val

def reverse_hash_correct(target_hash):
    """
    Correctly reverse the hash by working backwards.
    Key insight: hash mod 33 = char mod 33
    """
    target = target_hash & 0xFFFFFFFF
    initial = 0x1505
    
    result = []
    current = target
    
    max_iter = 100
    
    for i in range(max_iter):
        if current == initial:
            break
        
        # hash mod 33 = char mod 33
        char_mod = current % 33
        
        found = False
        # Try characters that match the modulo
        for char_val in range(32, 127):
            if char_val % 33 == char_mod:
                # Calculate previous hash
                # current = (prev * 33 + char) mod 2^32
                # We need: prev * 33 = (current - char) mod 2^32
                diff = (current - char_val) % (2**32)
                
                if diff % 33 == 0:
                    prev_hash = (diff // 33) & 0xFFFFFFFF
                    
                    # Check if valid
                    if prev_hash >= initial or prev_hash == initial:
                        result.insert(0, chr(char_val))
                        current = prev_hash
                        found = True
                        break
        
        if not found:
            # If no exact match, try all characters (fallback)
            for char_val in range(32, 127):
                diff = (current - char_val) % (2**32)
                if diff % 33 == 0:
                    prev_hash = (diff // 33) & 0xFFFFFFFF
                    if prev_hash >= initial or prev_hash == initial:
                        result.insert(0, chr(char_val))
                        current = prev_hash
                        found = True
                        break
        
        if not found:
            print(f"Stopped at iteration {i}, current hash: 0x{current:x}")
            break
    
    if current == initial:
        return ''.join(result)
    return None

print("Reversing hash 0x72d59e59...")
print("Using modulo property: hash mod 33 = char mod 33")
print()

result = reverse_hash_correct(0x72d59e59)

if result:
    print(f"\n[+] Found flag: {result}")
    print(f"[+] Verification: hash = 0x{hash_string(result):08x}")
    print(f"[+] Target hash: 0x72d59e59")
    if hash_string(result) == 0x72d59e59:
        print("[+] CORRECT! This is the flag!")
    else:
        print("[!] Hash doesn't match exactly")
else:
    print("[-] Could not reverse hash")

