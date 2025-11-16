#!/usr/bin/env python3
"""
Reverse the hash using a more efficient approach.
Hash: hash = hash * 33 + char, starting from 0x1505
Target: 0x72d59e59
"""

def hash_string(s):
    """Hash function matching the binary"""
    hash_val = 0x1505
    for c in s:
        hash_val = ((hash_val << 5) + hash_val + ord(c)) & 0xFFFFFFFF
    return hash_val

def reverse_hash(target_hash, max_length=50):
    """
    Work backwards from target hash.
    If hash = prev_hash * 33 + char, then:
    prev_hash = (hash - char) / 33
    
    We need to find a sequence that ends at 0x1505.
    """
    target = target_hash & 0xFFFFFFFF
    initial = 0x1505
    
    # Use BFS to find the shortest path
    from collections import deque
    
    # Queue: (current_hash, path_string, depth)
    queue = deque([(target, "", 0)])
    visited = set([target])
    
    max_depth = max_length
    
    while queue:
        current_hash, path, depth = queue.popleft()
        
        if depth > max_depth:
            continue
        
        # Try all possible characters
        for char_val in range(32, 127):
            # Calculate previous hash
            # current = prev * 33 + char
            # prev = (current - char) / 33
            diff = (current_hash - char_val) % (2**32)
            
            if diff % 33 == 0:
                prev_hash = (diff // 33) & 0xFFFFFFFF
                
                # Check if we reached the initial hash
                if prev_hash == initial:
                    result = chr(char_val) + path
                    # Verify
                    if hash_string(result) == target:
                        return result
                
                # Add to queue if not visited
                if prev_hash not in visited and prev_hash >= initial:
                    visited.add(prev_hash)
                    queue.append((prev_hash, chr(char_val) + path, depth + 1))
    
    return None

# Try with z3 if available
try:
    from z3 import *
    print("Using Z3 solver...")
    
    def solve_with_z3(target_hash, max_length=30):
        """Use Z3 to solve for the flag"""
        s = Solver()
        
        # Create character variables
        chars = [BitVec(f'c{i}', 8) for i in range(max_length)]
        
        # Constraints: printable ASCII
        for c in chars:
            s.add(c >= 32, c < 127)
        
        # Hash calculation
        hash_val = BitVecVal(0x1505, 32)
        for c in chars:
            hash_val = (hash_val << 5) + hash_val + ZeroExt(24, c)
            hash_val = hash_val & 0xFFFFFFFF
        
        # Target hash
        s.add(hash_val == target_hash)
        
        # Try to find a solution
        if s.check() == sat:
            model = s.model()
            result = ''.join(chr(model[c].as_long()) for c in chars)
            # Remove trailing nulls
            result = result.rstrip('\x00')
            return result
        return None
    
    result = solve_with_z3(0x72d59e59, max_length=30)
    if result:
        print(f"[+] Found with Z3: {result}")
        print(f"[+] Verification: hash = 0x{hash_string(result):08x}")
        if hash_string(result) == 0x72d59e59:
            print("[+] CORRECT!")
            exit(0)
except ImportError:
    print("Z3 not available, using BFS approach...")

# Use BFS approach
print("Using BFS to reverse hash...")
result = reverse_hash(0x72d59e59, max_length=40)

if result:
    print(f"\n[+] Found flag: {result}")
    print(f"[+] Verification: hash = 0x{hash_string(result):08x}")
    if hash_string(result) == 0x72d59e59:
        print("[+] CORRECT!")
    else:
        print("[!] Hash doesn't match")
else:
    print("[-] Could not reverse hash")
    print("\nTrying brute force with common patterns...")
    
    # Try some variations
    test_patterns = [
        "CS{" + "A" * i + "}" for i in range(10, 30)
    ]
    
    for pattern in test_patterns:
        h = hash_string(pattern)
        if h == 0x72d59e59:
            print(f"[+] Found: {pattern}")
            break

