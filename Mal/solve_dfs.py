#!/usr/bin/env python3
"""
DFS approach to explore all paths systematically
"""

def hash_string(s):
    hash_val = 0x1505
    for c in s:
        hash_val = ((hash_val << 5) + hash_val + ord(c)) & 0xFFFFFFFF
    return hash_val

def get_prev_hashes(current_hash):
    """Get all valid (prev_hash, char) pairs"""
    results = []
    for char_val in range(32, 127):
        diff = (current_hash - char_val) % (2**32)
        if diff % 33 == 0:
            prev_hash = (diff // 33) & 0xFFFFFFFF
            verify = ((prev_hash * 33 + char_val) & 0xFFFFFFFF)
            if verify == current_hash:
                results.append((prev_hash, chr(char_val)))
    return results

def dfs(current_hash, path, initial_hash, visited, max_depth, depth=0):
    """DFS to find path from current to initial"""
    if depth > max_depth:
        return None
    
    if current_hash == initial_hash:
        return path
    
    if current_hash < initial_hash:
        return None  # Can't go below initial
    
    # Avoid cycles (but allow revisiting if we have a different path length)
    if (current_hash, len(path)) in visited:
        return None
    visited.add((current_hash, len(path)))
    
    # Get all valid previous hashes
    prev_options = get_prev_hashes(current_hash)
    
    # Try all options
    for prev_hash, char in prev_options:
        if prev_hash >= initial_hash:
            result = dfs(prev_hash, char + path, initial_hash, visited.copy(), max_depth, depth + 1)
            if result is not None:
                return result
    
    return None

# Main
target = 0x72d59e59
initial = 0x1505

print("DFS Hash Reversal")
print(f"Target: 0x{target:x}, Initial: 0x{initial:x}")
print()

# Try increasing max depths
for max_depth in range(20, 101, 5):
    print(f"Trying max depth {max_depth}...")
    visited = set()
    result = dfs(target, "", initial, visited, max_depth)
    
    if result:
        print(f"\n[+] FLAG FOUND: {result}")
        print(f"[+] Verification: 0x{hash_string(result):08x}")
        if hash_string(result) == target:
            print("[+] CORRECT!")
        break
    else:
        print(f"  No solution found (explored {len(visited)} states)")

if not result:
    print("\n[-] Could not find flag with DFS")

