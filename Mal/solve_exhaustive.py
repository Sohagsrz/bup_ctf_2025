#!/usr/bin/env python3
"""
Exhaustive search with increased limits and better state tracking
"""

def hash_string(s):
    hash_val = 0x1505
    for c in s:
        hash_val = ((hash_val << 5) + hash_val + ord(c)) & 0xFFFFFFFF
    return hash_val

def get_prev_hashes(current_hash):
    results = []
    for char_val in range(32, 127):
        diff = (current_hash - char_val) % (2**32)
        if diff % 33 == 0:
            prev_hash = (diff // 33) & 0xFFFFFFFF
            verify = ((prev_hash * 33 + char_val) & 0xFFFFFFFF)
            if verify == current_hash:
                results.append((prev_hash, chr(char_val)))
    return results

def reverse_exhaustive(target_hash, initial_hash):
    """Exhaustive BFS with very large limits"""
    from collections import deque
    
    queue = deque([(target_hash, "")])
    visited = {}  # hash -> min_path_length
    
    iteration = 0
    max_iterations = 50000000  # Very large
    max_length = 200  # Allow longer paths
    
    print(f"Exhaustive search: 0x{target_hash:x} -> 0x{initial_hash:x}")
    print(f"Max iterations: {max_iterations}, Max length: {max_length}")
    print()
    
    while queue:
        iteration += 1
        
        if iteration > max_iterations:
            print(f"\nReached limit after {iteration} iterations")
            print(f"Visited {len(visited)} unique states")
            break
        
        current_hash, path = queue.popleft()
        path_len = len(path)
        
        if path_len > max_length:
            continue
        
        if current_hash == initial_hash:
            return path
        
        # Track minimum path length to reach this state
        if current_hash not in visited or visited[current_hash] > path_len:
            visited[current_hash] = path_len
        elif visited[current_hash] < path_len:
            continue  # We've seen this state with a shorter path
        
        # Get all valid previous hashes
        prev_options = get_prev_hashes(current_hash)
        
        for prev_hash, char in prev_options:
            if prev_hash >= initial_hash:
                queue.append((prev_hash, char + path))
        
        if iteration % 1000000 == 0:
            print(f"  Iter {iteration}: visited {len(visited)}, queue {len(queue)}, path_len {path_len}")
    
    return None

target = 0x72d59e59
initial = 0x1505

result = reverse_exhaustive(target, initial)

if result:
    print(f"\n[+] FLAG: {result}")
    print(f"Verification: 0x{hash_string(result):08x} == 0x{target:08x}")
else:
    print("\n[-] Not found")

