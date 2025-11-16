#!/usr/bin/env python3
"""
Final attempt: Use backward search but prioritize readable characters
"""

def hash_string(s):
    hash_val = 0x1505
    for c in s:
        hash_val = ((hash_val << 5) + hash_val + ord(c)) & 0xFFFFFFFF
    return hash_val

def get_prev_options(current_hash):
    """Get all valid (prev_hash, char) pairs, sorted by character preference"""
    results = []
    char_mod = current_hash % 33
    
    # Character preference: alphanumeric first, then common symbols
    char_priority = {}
    for i, c in enumerate("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}-"):
        char_priority[ord(c)] = i
    
    for char_val in range(32, 127):
        if char_val % 33 == char_mod:
            diff = (current_hash - char_val) % (2**32)
            if diff % 33 == 0:
                prev_hash = (diff // 33) & 0xFFFFFFFF
                verify = ((prev_hash * 33 + char_val) & 0xFFFFFFFF)
                if verify == current_hash:
                    priority = char_priority.get(char_val, 1000)
                    results.append((prev_hash, chr(char_val), priority))
    
    # Sort by priority (lower = better)
    results.sort(key=lambda x: x[2])
    return [(h, c) for h, c, p in results]

def reverse_dfs_prioritized(target_hash, initial_hash, max_depth=40):
    """DFS with character priority"""
    best_solution = None
    best_readability = float('inf')
    
    def dfs(current_hash, path, depth, visited):
        nonlocal best_solution, best_readability
        
        if depth > max_depth:
            return None
        
        if current_hash == initial_hash:
            # Calculate readability score (lower = more readable)
            score = sum(1 for c in path if c.isalnum() or c in "_{}-")
            if score < best_readability:
                best_readability = score
                best_solution = path
            return path
        
        if current_hash in visited:
            return None
        
        visited.add(current_hash)
        
        prev_options = get_prev_options(current_hash)
        
        for prev_hash, char in prev_options:
            if prev_hash >= initial_hash:
                result = dfs(prev_hash, char + path, depth + 1, visited.copy())
                if result:
                    return result
        
        return None
    
    visited = set()
    result = dfs(target_hash, "", 0, visited)
    
    return result if result else best_solution

target = 0x72d59e59
initial = 0x1505

print("=" * 70)
print("Prioritized backward search for readable flag...")
print("=" * 70)
print(f"Target: 0x{target:08x}")
print(f"Initial: 0x{initial:08x}")
print()

result = reverse_dfs_prioritized(target, initial, max_depth=35)

if result:
    print(f"\n[+] Found: {result}")
    h = hash_string(result)
    print(f"[+] Hash: 0x{h:08x}")
    if h == target:
        print("[+] CORRECT!")
        print(f"\n{'='*70}")
        print(f"FLAG: {result}")
        print(f"{'='*70}")
    else:
        print("[!] Hash mismatch")
else:
    print("[-] Could not find solution")


