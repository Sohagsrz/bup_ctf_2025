#!/usr/bin/env python3
"""
Fast hash reversal using the modulo property.
Key insight: hash mod 33 = char mod 33
"""

def hash_string(s):
    hash_val = 0x1505
    for c in s:
        hash_val = ((hash_val << 5) + hash_val + ord(c)) & 0xFFFFFFFF
    return hash_val

def reverse_hash_fast(target_hash, max_length=50):
    """Fast reverse using modulo property"""
    target = target_hash & 0xFFFFFFFF
    initial = 0x1505
    
    result = []
    current = target
    
    for i in range(max_length):
        if current == initial:
            break
        
        # Key: hash mod 33 = char mod 33
        char_mod = current % 33
        
        found = False
        # Only try characters that match the modulo
        for char_val in range(32, 127):
            if char_val % 33 == char_mod:
                # Verify: (prev * 33 + char) mod 2^32 == current
                diff = (current - char_val) % (2**32)
                if diff % 33 == 0:
                    prev_hash = (diff // 33) & 0xFFFFFFFF
                    # Verify the calculation
                    verify = ((prev_hash * 33 + char_val) & 0xFFFFFFFF)
                    if verify == current and prev_hash >= initial:
                        result.insert(0, chr(char_val))
                        current = prev_hash
                        found = True
                        break
        
        if not found:
            print(f"Stopped at step {i}, hash: 0x{current:x}")
            return None
    
    if current == initial:
        return ''.join(result)
    return None

print("Fast hash reversal...")
result = reverse_hash_fast(0x72d59e59, max_length=60)

if result:
    print(f"\n[+] FLAG: {result}")
    print(f"[+] Verification: 0x{hash_string(result):08x} == 0x72d59e59")
    if hash_string(result) == 0x72d59e59:
        print("[+] CORRECT!")
else:
    print("[-] Could not reverse")

