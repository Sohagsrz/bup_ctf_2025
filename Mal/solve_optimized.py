#!/usr/bin/env python3
"""
Optimized BFS with better state management
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

def reverse_optimized(target_hash, initial_hash):
    from collections import deque
    import sys
    
    queue = deque([(target_hash, "")])
    # Use set for O(1) lookup - only track hash values we've seen
    visited = set([target_hash])
    
    iteration = 0
    max_iterations = 100000000  # Very large
    max_length = 300  # Allow very long paths
    
    print(f"Optimized BFS: 0x{target_hash:x} -> 0x{initial_hash:x}")
    print(f"Max iterations: {max_iterations}, Max length: {max_length}")
    print()
    
    while queue:
        iteration += 1
        
        if iteration > max_iterations:
            print(f"\nReached limit: {max_iterations} iterations")
            print(f"Visited: {len(visited)} states")
            break
        
        current_hash, path = queue.popleft()
        
        if len(path) > max_length:
            continue
        
        if current_hash == initial_hash:
            return path
        
        # Get all valid previous hashes
        prev_options = get_prev_hashes(current_hash)
        
        for prev_hash, char in prev_options:
            if prev_hash >= initial_hash and prev_hash not in visited:
                visited.add(prev_hash)
                queue.append((prev_hash, char + path))
        
        if iteration % 5000000 == 0:
            print(f"  Iter {iteration}: visited {len(visited)}, queue {len(queue)}, path_len {len(path)}")
            sys.stdout.flush()
    
    return None

target = 0x72d59e59
initial = 0x1505

print("=" * 70)
result = reverse_optimized(target, initial)

if result:
    print(f"\n[+] FLAG: {result}")
    print(f"Verification: 0x{hash_string(result):08x} == 0x{target:08x}")
    if hash_string(result) == target:
        print("✓ CORRECT!")
else:
    print("\n[-] Not found")

