#!/usr/bin/env python3
"""
Bidirectional search: from target backwards AND from initial forwards
Meet in the middle
"""

def hash_string(s):
    hash_val = 0x1505
    for c in s:
        hash_val = ((hash_val << 5) + hash_val + ord(c)) & 0xFFFFFFFF
    return hash_val

def get_prev_hashes(current_hash):
    """Get all valid (prev_hash, char) pairs going backwards"""
    results = []
    for char_val in range(32, 127):
        diff = (current_hash - char_val) % (2**32)
        if diff % 33 == 0:
            prev_hash = (diff // 33) & 0xFFFFFFFF
            verify = ((prev_hash * 33 + char_val) & 0xFFFFFFFF)
            if verify == current_hash:
                results.append((prev_hash, chr(char_val)))
    return results

def get_next_hashes(current_hash):
    """Get all valid (next_hash, char) pairs going forwards"""
    results = []
    for char_val in range(32, 127):
        next_hash = ((current_hash * 33 + char_val) & 0xFFFFFFFF)
        results.append((next_hash, chr(char_val)))
    return results

def bidirectional_search(target_hash, initial_hash, max_depth=20):
    """Bidirectional BFS"""
    from collections import deque
    
    # Forward: from initial_hash, track: hash -> (path_string, depth)
    forward_queue = deque([(initial_hash, "", 0)])
    forward_visited = {initial_hash: ("", 0)}
    
    # Backward: from target_hash
    backward_queue = deque([(target_hash, "", 0)])
    backward_visited = {target_hash: ("", 0)}
    
    iteration = 0
    max_iterations = 10000000
    
    print(f"Bidirectional search: 0x{initial_hash:x} <-> 0x{target_hash:x}")
    print(f"Max depth per direction: {max_depth}")
    print()
    
    while (forward_queue or backward_queue) and iteration < max_iterations:
        iteration += 1
        
        # Expand forward
        if forward_queue:
            current_hash, path, depth = forward_queue.popleft()
            
            if depth < max_depth:
                next_options = get_next_hashes(current_hash)
                for next_hash, char in next_options:
                    if next_hash not in forward_visited:
                        new_path = path + char
                        forward_visited[next_hash] = (new_path, depth + 1)
                        forward_queue.append((next_hash, new_path, depth + 1))
                        
                        # Check if we met
                        if next_hash in backward_visited:
                            backward_path, _ = backward_visited[next_hash]
                            # Reverse the backward path
                            full_path = new_path + backward_path[::-1]
                            return full_path
        
        # Expand backward
        if backward_queue:
            current_hash, path, depth = backward_queue.popleft()
            
            if depth < max_depth:
                prev_options = get_prev_hashes(current_hash)
                for prev_hash, char in prev_options:
                    if prev_hash >= initial_hash and prev_hash not in backward_visited:
                        new_path = char + path
                        backward_visited[prev_hash] = (new_path, depth + 1)
                        backward_queue.append((prev_hash, new_path, depth + 1))
                        
                        # Check if we met
                        if prev_hash in forward_visited:
                            forward_path, _ = forward_visited[prev_hash]
                            # The backward path is already reversed
                            full_path = forward_path + new_path
                            return full_path
        
        if iteration % 100000 == 0:
            print(f"  Iter {iteration}: forward={len(forward_visited)}, backward={len(backward_visited)}")
    
    return None

target = 0x72d59e59
initial = 0x1505

print("=" * 70)
print("Bidirectional Hash Reversal")
print("=" * 70)
print()

# Try increasing depths
for depth in [10, 15, 20, 25]:
    print(f"Trying depth {depth}...")
    result = bidirectional_search(target, initial, max_depth=depth)
    
    if result:
        print(f"\n[+] FLAG FOUND: {result}")
        print(f"[+] Verification: 0x{hash_string(result):08x} == 0x{target:08x}")
        if hash_string(result) == target:
            print("[+] CORRECT!")
        break
    else:
        print(f"  No solution found at depth {depth}")

if not result:
    print("\n[-] Could not find flag with bidirectional search")

