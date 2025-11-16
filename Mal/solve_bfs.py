#!/usr/bin/env python3
"""
BFS approach to reverse hash - explores all valid paths
"""

def hash_string(s):
    hash_val = 0x1505
    for c in s:
        hash_val = ((hash_val << 5) + hash_val + ord(c)) & 0xFFFFFFFF
    return hash_val

def reverse_hash_bfs(target_hash, max_length=50):
    """BFS to find all paths from target to initial"""
    from collections import deque
    
    target = target_hash & 0xFFFFFFFF
    initial = 0x1505
    
    # Queue: (current_hash, path_string)
    queue = deque([(target, "")])
    visited = {target}
    
    iteration = 0
    while queue and iteration < 100000:  # Limit iterations
        iteration += 1
        current_hash, path = queue.popleft()
        
        if len(path) > max_length:
            continue
        
        if current_hash == initial:
            return path
        
        # Find all valid previous hashes
        for char_val in range(32, 127):
            # Calculate: prev_hash = (current - char) / 33
            diff = (current_hash - char_val) % (2**32)
            
            if diff % 33 == 0:
                prev_hash = (diff // 33) & 0xFFFFFFFF
                
                # Verify: (prev * 33 + char) mod 2^32 == current
                verify = ((prev_hash * 33 + char_val) & 0xFFFFFFFF)
                if verify == current_hash and prev_hash >= initial:
                    if prev_hash not in visited:
                        visited.add(prev_hash)
                        queue.append((prev_hash, chr(char_val) + path))
        
        if iteration % 10000 == 0:
            print(f"  Explored {iteration} states, queue size: {len(queue)}, path length: {len(path)}")
    
    return None

print("BFS hash reversal...")
result = reverse_hash_bfs(0x72d59e59, max_length=60)

if result:
    print(f"\n[+] FLAG: {result}")
    print(f"[+] Verification: 0x{hash_string(result):08x} == 0x72d59e59")
    if hash_string(result) == 0x72d59e59:
        print("[+] CORRECT!")
else:
    print("[-] Could not reverse (may need more iterations or different approach)")

