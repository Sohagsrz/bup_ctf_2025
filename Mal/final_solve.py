#!/usr/bin/env python3
"""
Final attempt to solve the hash reversal.
Using a more systematic approach with better modulo handling.
"""

def hash_string(s):
    """Hash function matching the binary"""
    hash_val = 0x1505
    for c in s:
        hash_val = ((hash_val << 5) + hash_val + ord(c)) & 0xFFFFFFFF
    return hash_val

def reverse_hash_systematic(target_hash):
    """
    Systematic reverse: work backwards character by character.
    For each step, we need to find char such that:
    (prev_hash * 33 + char) mod 2^32 = current_hash
    
    This means: prev_hash = (current_hash - char) / 33
    We need (current_hash - char) mod 2^32 to be divisible by 33.
    """
    target = target_hash & 0xFFFFFFFF
    initial = 0x1505
    
    # Use DFS with memoization
    memo = {}
    
    def dfs(current_hash, path, depth, max_depth):
        if depth > max_depth:
            return None
        
        if current_hash == initial:
            return path
        
        if current_hash in memo:
            return None  # Already explored this path
        
        memo[current_hash] = True
        
        # Try all characters
        for char_val in range(32, 127):
            # Calculate: prev_hash = (current - char) / 33
            # Need: (current - char) mod 2^32 divisible by 33
            diff = (current_hash - char_val) % (2**32)
            
            if diff % 33 == 0:
                prev_hash = (diff // 33) & 0xFFFFFFFF
                
                # Recursively search
                result = dfs(prev_hash, chr(char_val) + path, depth + 1, max_depth)
                if result is not None:
                    return result
        
        return None
    
    # Try increasing max depths
    for max_depth in range(10, 50):
        print(f"Trying max depth {max_depth}...")
        memo.clear()
        result = dfs(target, "", 0, max_depth)
        if result:
            return result
    
    return None

print("Systematic hash reversal...")
result = reverse_hash_systematic(0x72d59e59)

if result:
    print(f"\n[+] Found flag: {result}")
    print(f"[+] Verification: hash = 0x{hash_string(result):08x}")
    if hash_string(result) == 0x72d59e59:
        print("[+] CORRECT!")
    else:
        print("[!] Hash mismatch")
else:
    print("[-] Could not reverse")

