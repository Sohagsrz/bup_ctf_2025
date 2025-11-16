#!/usr/bin/env python3
"""
Complete BFS exploring ALL branches - no greedy selection
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

def reverse_hash_complete(target_hash, initial_hash, max_length=150):
    """Complete BFS - explore ALL branches"""
    from collections import deque
    
    queue = deque([(target_hash, "")])
    # Track visited states: (hash, path_length) to allow different paths
    visited = {}
    
    iteration = 0
    max_iterations = 10000000
    
    print(f"Complete BFS: 0x{target_hash:x} -> 0x{initial_hash:x}")
    print(f"Max length: {max_length}, Max iterations: {max_iterations}")
    print()
    
    best_distance = target_hash - initial_hash
    last_report = 0
    
    while queue:
        iteration += 1
        
        if iteration > max_iterations:
            print(f"\nReached iteration limit")
            break
        
        current_hash, path = queue.popleft()
        path_len = len(path)
        
        if path_len > max_length:
            continue
        
        if current_hash == initial_hash:
            return path
        
        # Track best progress
        distance = current_hash - initial_hash
        if distance < best_distance:
            best_distance = distance
            if iteration - last_report > 100000:
                print(f"  Iter {iteration}: best distance = {best_distance}, path_len = {path_len}, queue = {len(queue)}")
                last_report = iteration
        
        # Get all valid previous hashes
        prev_options = get_prev_hashes(current_hash)
        
        for prev_hash, char in prev_options:
            if prev_hash >= initial_hash:
                next_path = char + path
                next_len = path_len + 1
                
                # Check if we've seen this state with same or shorter path
                state_key = prev_hash
                if state_key not in visited or visited[state_key] > next_len:
                    visited[state_key] = next_len
                    queue.append((prev_hash, next_path))
    
    return None

# Main
target = 0x72d59e59
initial = 0x1505

print("=" * 70)
print("Complete Hash Reversal")
print("=" * 70)
print()

result = reverse_hash_complete(target, initial, max_length=150)

if result:
    print()
    print("=" * 70)
    print(f"[+] FLAG FOUND: {result}")
    print("=" * 70)
    print(f"Length: {len(result)} characters")
    print(f"Verification: 0x{hash_string(result):08x} == 0x{target:08x}")
    
    if hash_string(result) == target:
        print("✓ CORRECT!")
else:
    print("\n[-] Could not find flag")

