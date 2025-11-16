#!/usr/bin/env python3
"""
Heuristic search: prioritize paths that minimize distance to initial hash
"""

def hash_string(s):
    hash_val = 0x1505
    for c in s:
        hash_val = ((hash_val << 5) + hash_val + ord(c)) & 0xFFFFFFFF
    return hash_val

def get_prev_hashes_correct(current_hash):
    results = []
    for char_val in range(32, 127):
        diff = (current_hash - char_val) % (2**32)
        for k in range(33):
            candidate = diff + k * (2**32)
            if candidate % 33 == 0:
                prev_hash = (candidate // 33) & 0xFFFFFFFF
                verify = ((prev_hash * 33 + char_val) & 0xFFFFFFFF)
                if verify == current_hash:
                    results.append((prev_hash, chr(char_val)))
                    break
    return results

def heuristic_search(target_hash, initial_hash, max_depth=50):
    from heapq import heappush, heappop
    
    # Priority queue: (priority, hash, path)
    # Priority = distance to initial + path_length (to prefer shorter paths)
    queue = [(target_hash - initial_hash, target_hash, "")]
    visited = set()
    
    iteration = 0
    max_iterations = 10000000
    
    print(f"Heuristic search: 0x{target_hash:x} -> 0x{initial_hash:x}")
    print(f"Max depth: {max_depth}")
    print()
    
    while queue:
        iteration += 1
        
        if iteration > max_iterations:
            print(f"\nReached limit: {max_iterations}")
            break
        
        priority, current_hash, path = heappop(queue)
        path_len = len(path)
        
        if path_len > max_depth:
            continue
        
        if current_hash == initial_hash:
            return path
        
        # Skip if we've seen this state with same or shorter path
        state_key = (current_hash, path_len)
        if state_key in visited:
            continue
        visited.add(state_key)
        
        # Get all valid previous hashes
        prev_options = get_prev_hashes_correct(current_hash)
        
        for prev_hash, char in prev_options:
            if prev_hash >= initial_hash:
                distance = prev_hash - initial_hash
                new_priority = distance + path_len + 1  # Prefer shorter paths
                heappush(queue, (new_priority, prev_hash, char + path))
        
        if iteration % 100000 == 0:
            print(f"  Iter {iteration}: queue {len(queue)}, path_len {path_len}, distance {current_hash - initial_hash}")
    
    return None

target = 0x72d59e59
initial = 0x1505

print("=" * 70)
result = heuristic_search(target, initial, max_depth=60)

if result:
    print(f"\n[+] FLAG: {result}")
    print(f"Verification: 0x{hash_string(result):08x} == 0x{target:08x}")
    if hash_string(result) == target:
        print("✓ CORRECT!")
else:
    print("\n[-] Not found")

