#!/usr/bin/env python3
"""
Working BFS implementation for hash reversal
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

def reverse_hash_bfs(target_hash, initial_hash, max_length=100):
    """BFS to find path from target to initial"""
    from collections import deque
    
    queue = deque([(target_hash, "")])
    # Use (hash, path_length) as visited key to allow different paths of same length
    visited = set([(target_hash, 0)])
    
    iteration = 0
    max_iterations = 5000000  # Large limit
    
    print(f"BFS from 0x{target_hash:x} to 0x{initial_hash:x}")
    print("Exploring all paths...")
    
    while queue:
        iteration += 1
        
        if iteration > max_iterations:
            print(f"\nReached iteration limit ({max_iterations})")
            print(f"Explored {len(visited)} unique states")
            break
        
        current_hash, path = queue.popleft()
        
        if len(path) > max_length:
            continue
        
        if current_hash == initial_hash:
            return path
        
        # Get all valid previous hashes
        prev_options = get_prev_hashes(current_hash)
        
        for prev_hash, char in prev_options:
            if prev_hash >= initial_hash:
                path_len = len(path) + 1
                state_key = (prev_hash, path_len)
                
                if state_key not in visited:
                    visited.add(state_key)
                    queue.append((prev_hash, char + path))
        
        if iteration % 100000 == 0:
            print(f"  Iter {iteration}: visited {len(visited)} states, queue: {len(queue)}, path_len: {len(path)}")
    
    return None

# Main
target = 0x72d59e59
initial = 0x1505

print("=" * 70)
print("Hash Reversal - Finding Flag")
print("=" * 70)
print(f"Target hash: 0x{target:08x}")
print(f"Initial hash: 0x{initial:08x}")
print("=" * 70)
print()

result = reverse_hash_bfs(target, initial, max_length=100)

if result:
    print()
    print("=" * 70)
    print(f"[+] FLAG FOUND: {result}")
    print("=" * 70)
    print(f"Verification:")
    print(f"  Computed hash: 0x{hash_string(result):08x}")
    print(f"  Target hash:   0x{target:08x}")
    
    if hash_string(result) == target:
        print("  ✓ HASH MATCHES - THIS IS THE CORRECT FLAG!")
    else:
        print("  ✗ Hash mismatch")
else:
    print("\n[-] Could not find flag")
    print("    May need more iterations or different approach")

