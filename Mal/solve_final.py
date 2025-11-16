#!/usr/bin/env python3
"""
Final hash reversal with proper backtracking.
The key insight: when working backwards, we need to handle modulo arithmetic correctly.
"""

def hash_string(s):
    """Hash function matching the binary"""
    hash_val = 0x1505
    for c in s:
        hash_val = ((hash_val << 5) + hash_val + ord(c)) & 0xFFFFFFFF
    return hash_val

def reverse_hash_backtrack(target_hash, max_length=50):
    """
    Reverse hash using backtracking with proper modulo handling.
    """
    target = target_hash & 0xFFFFFFFF
    initial = 0x1505
    
    def backtrack(current_hash, path, depth):
        if depth > max_length:
            return None
        
        if current_hash == initial:
            return path
        
        # Try all characters
        candidates = []
        for char_val in range(32, 127):
            # Calculate previous hash
            # current = (prev * 33 + char) mod 2^32
            # We need: prev * 33 = (current - char) mod 2^32
            
            # Handle modulo arithmetic correctly
            diff = (current_hash - char_val) % (2**32)
            
            # Check if divisible by 33
            if diff % 33 == 0:
                prev_hash = (diff // 33) & 0xFFFFFFFF
                
                # Also need to check: (prev_hash * 33 + char_val) mod 2^32 == current_hash
                # This verifies our calculation
                verify = ((prev_hash * 33 + char_val) & 0xFFFFFFFF)
                if verify == current_hash:
                    candidates.append((prev_hash, chr(char_val)))
        
        # Try candidates (prioritize those closer to initial)
        candidates.sort(key=lambda x: abs(x[0] - initial))
        
        for prev_hash, char in candidates:
            if prev_hash >= initial or prev_hash == initial:
                result = backtrack(prev_hash, char + path, depth + 1)
                if result is not None:
                    return result
        
        return None
    
    return backtrack(target, "", 0)

print("Reversing hash 0x72d59e59 with backtracking...")
print("This may take a while...")

for max_len in range(15, 45):
    print(f"Trying max length {max_len}...")
    result = reverse_hash_backtrack(0x72d59e59, max_len)
    if result:
        print(f"\n[+] Found flag: {result}")
        print(f"[+] Verification: hash = 0x{hash_string(result):08x}")
        if hash_string(result) == 0x72d59e59:
            print("[+] CORRECT! This is the flag!")
            break
        else:
            print("[!] Hash doesn't match, continuing...")

