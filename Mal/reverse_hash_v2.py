#!/usr/bin/env python3
"""
Better approach: Use constraint solving or efficient brute force
"""

def hash_string(s):
    """Hash function matching the binary"""
    hash_val = 0x1505
    for c in s:
        hash_val = ((hash_val << 5) + hash_val + ord(c)) & 0xFFFFFFFF
    return hash_val

def find_flag_backwards(target_hash):
    """
    Work backwards more efficiently.
    We know: hash = prev_hash * 33 + char
    So: prev_hash = (hash - char) / 33
    We need to find a sequence that ends at 0x1505
    """
    target = target_hash & 0xFFFFFFFF
    initial = 0x1505
    
    # Use dynamic programming / memoization
    # Try to find a path from target to initial
    
    def find_path(current_hash, path, depth, max_depth):
        if depth > max_depth:
            return None
        
        if current_hash == initial:
            return path
        
        # Try all possible characters
        for char_val in range(32, 127):
            # Calculate previous hash
            # current = prev * 33 + char
            # prev = (current - char) / 33
            diff = (current_hash - char_val) % (2**32)
            
            if diff % 33 == 0:
                prev_hash = (diff // 33) & 0xFFFFFFFF
                
                # Recursively try
                result = find_path(prev_hash, [chr(char_val)] + path, depth + 1, max_depth)
                if result:
                    return result
        
        return None
    
    # Try different max depths
    for max_len in range(10, 50):
        print(f"Trying max length {max_len}...")
        result = find_path(target, [], 0, max_len)
        if result:
            return ''.join(result)
    
    return None

# Try a different approach: use the fact that we can work character by character
def find_flag_iterative(target_hash):
    """Iterative approach working backwards"""
    target = target_hash & 0xFFFFFFFF
    initial = 0x1505
    
    # Build the string backwards
    result = []
    current = target
    
    # Limit iterations to prevent infinite loops
    max_iter = 100
    
    for i in range(max_iter):
        if current == initial:
            break
        
        found = False
        # Try characters in reverse order (more likely to be letters/digits)
        for char_val in range(126, 31, -1):
            diff = (current - char_val) % (2**32)
            if diff % 33 == 0:
                prev = (diff // 33) & 0xFFFFFFFF
                if prev >= initial or prev == initial:
                    result.insert(0, chr(char_val))
                    current = prev
                    found = True
                    break
        
        if not found:
            # Try forward order
            for char_val in range(32, 127):
                diff = (current - char_val) % (2**32)
                if diff % 33 == 0:
                    prev = (diff // 33) & 0xFFFFFFFF
                    if prev >= initial or prev == initial:
                        result.insert(0, chr(char_val))
                        current = prev
                        found = True
                        break
        
        if not found:
            break
    
    if current == initial:
        return ''.join(result)
    return None

print("Attempting iterative reverse...")
result = find_flag_iterative(0x72d59e59)

if result:
    print(f"\n[+] Found: {result}")
    print(f"[+] Verification: hash = 0x{hash_string(result):08x}")
    if hash_string(result) == 0x72d59e59:
        print("[+] CORRECT!")
    else:
        print("[!] Hash doesn't match")
else:
    print("[-] Iterative approach failed")
    print("\nTrying recursive approach...")
    result = find_flag_backwards(0x72d59e59)
    if result:
        print(f"\n[+] Found: {result}")
        print(f"[+] Verification: hash = 0x{hash_string(result):08x}")



