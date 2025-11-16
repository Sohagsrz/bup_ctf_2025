#!/usr/bin/env python3
"""
Efficient backward search with better pruning
"""

def hash_string(s):
    """Hash function matching the binary"""
    hash_val = 0x1505
    for c in s:
        hash_val = ((hash_val << 5) + hash_val + ord(c)) & 0xFFFFFFFF
    return hash_val

def get_prev_hash_char(current_hash):
    """Get all valid (prev_hash, char) pairs - optimized"""
    results = []
    char_mod = current_hash % 33
    
    # Only try characters that match the modulo
    for char_val in range(32, 127):
        if char_val % 33 == char_mod:
            diff = (current_hash - char_val) % (2**32)
            if diff % 33 == 0:
                prev_hash = (diff // 33) & 0xFFFFFFFF
                # Verify
                verify = ((prev_hash * 33 + char_val) & 0xFFFFFFFF)
                if verify == current_hash:
                    results.append((prev_hash, chr(char_val)))
    return results

def reverse_bfs_optimized(target_hash, initial_hash, max_length=50):
    """Optimized BFS with priority queue (closer to initial = higher priority)"""
    from collections import deque
    
    # Use deque with depth tracking
    queue = deque([(target_hash, "", 0)])
    visited = {}  # hash -> (path, depth)
    
    iteration = 0
    max_iterations = 5000000
    
    print(f"Optimized BFS: 0x{target_hash:08x} -> 0x{initial_hash:08x}")
    print(f"Max length: {max_length}")
    print()
    
    best_distance = float('inf')
    
    while queue and iteration < max_iterations:
        iteration += 1
        
        current_hash, path, depth = queue.popleft()
        
        if depth > max_length:
            continue
        
        if current_hash == initial_hash:
            return path
        
        # Calculate distance to initial
        distance = abs(current_hash - initial_hash) if current_hash >= initial_hash else float('inf')
        if distance < best_distance:
            best_distance = distance
            if iteration % 10000 == 0:
                print(f"  Iter {iteration}: depth={depth}, best_dist={best_distance}, path_len={len(path)}")
        
        # Get valid previous hashes
        prev_options = get_prev_hash_char(current_hash)
        
        # Sort by distance to initial (closer = better)
        prev_options.sort(key=lambda x: abs(x[0] - initial_hash) if x[0] >= initial_hash else float('inf'))
        
        for prev_hash, char in prev_options:
            if prev_hash >= initial_hash:
                if prev_hash not in visited or visited[prev_hash][1] > depth + 1:
                    visited[prev_hash] = (char + path, depth + 1)
                    queue.append((prev_hash, char + path, depth + 1))
    
    return None

# Also try DFS with limited depth
def reverse_dfs_limited(target_hash, initial_hash, max_depth=30):
    """DFS with depth limit"""
    visited = set()
    
    def dfs(current_hash, path, depth):
        if depth > max_depth:
            return None
        
        if current_hash == initial_hash:
            return path
        
        if current_hash in visited:
            return None
        
        visited.add(current_hash)
        
        prev_options = get_prev_hash_char(current_hash)
        # Try options closest to initial first
        prev_options.sort(key=lambda x: abs(x[0] - initial_hash) if x[0] >= initial_hash else float('inf'))
        
        for prev_hash, char in prev_options:
            if prev_hash >= initial_hash:
                result = dfs(prev_hash, char + path, depth + 1)
                if result:
                    return result
        
        return None
    
    return dfs(target_hash, "", 0)

target = 0x72d59e59
initial = 0x1505

print("=" * 70)
print("Trying optimized approaches...")
print("=" * 70)

# Try DFS first (faster for finding one solution)
print("\n1. Trying DFS with depth limit...")
result = reverse_dfs_limited(target, initial, max_depth=35)

if result:
    print(f"\n[+] DFS Found: {result}")
    print(f"[+] Verification: 0x{hash_string(result):08x}")
    if hash_string(result) == target:
        print("[+] CORRECT!")
        print(f"\n{'='*70}")
        print(f"FLAG: {result}")
        print(f"{'='*70}")
    else:
        print("[!] Hash mismatch, trying BFS...")
        result = None

if not result:
    print("\n2. Trying optimized BFS...")
    result = reverse_bfs_optimized(target, initial, max_length=50)
    
    if result:
        print(f"\n[+] BFS Found: {result}")
        print(f"[+] Verification: 0x{hash_string(result):08x}")
        if hash_string(result) == target:
            print("[+] CORRECT!")
            print(f"\n{'='*70}")
            print(f"FLAG: {result}")
            print(f"{'='*70}")
        else:
            print("[!] Hash mismatch")

if not result:
    print("\n[-] Could not find flag")


