#!/usr/bin/env python3
"""
Exhaustive search - explore EVERY branch, no early termination
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

def exhaustive_search(target_hash, initial_hash, max_depth=150):
    from collections import deque
    
    # Use a queue and explore ALL paths
    queue = deque([(target_hash, "")])
    # Track visited: hash -> set of path_lengths we've seen
    visited = {}
    
    iteration = 0
    max_iterations = 500000000  # Very large
    
    print(f"Exhaustive search: 0x{target_hash:x} -> 0x{initial_hash:x}")
    print(f"Max depth: {max_depth}, Max iterations: {max_iterations}")
    print()
    
    while queue:
        iteration += 1
        
        if iteration > max_iterations:
            print(f"\nReached iteration limit: {max_iterations}")
            print(f"Visited {len(visited)} unique states")
            break
        
        current_hash, path = queue.popleft()
        path_len = len(path)
        
        if path_len > max_depth:
            continue
        
        if current_hash == initial_hash:
            return path
        
        # Track visited states - allow revisiting if path is shorter
        if current_hash not in visited:
            visited[current_hash] = set()
        
        # Only skip if we've seen this state with same or shorter path
        if path_len in visited[current_hash]:
            continue
        
        visited[current_hash].add(path_len)
        
        # Get ALL valid previous hashes
        prev_options = get_prev_hashes(current_hash)
        
        for prev_hash, char in prev_options:
            if prev_hash >= initial_hash:
                queue.append((prev_hash, char + path))
        
        if iteration % 10000000 == 0:
            print(f"  Iter {iteration}: visited {len(visited)}, queue {len(queue)}, path_len {path_len}")
    
    return None

target = 0x72d59e59
initial = 0x1505

print("=" * 70)
result = exhaustive_search(target, initial, max_depth=200)

if result:
    print(f"\n[+] FLAG: {result}")
    print(f"Verification: 0x{hash_string(result):08x} == 0x{target:08x}")
    if hash_string(result) == target:
        print("✓ CORRECT!")
else:
    print("\n[-] Not found - may need more iterations or different approach")

