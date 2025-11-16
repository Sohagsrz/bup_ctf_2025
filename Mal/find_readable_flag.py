#!/usr/bin/env python3
"""
Find a longer, human-readable flag by working backwards
and filtering for readable character sequences
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
        for k in range(33):
            candidate = diff + k * (2**32)
            if candidate % 33 == 0:
                prev_hash = (candidate // 33) & 0xFFFFFFFF
                verify = ((prev_hash * 33 + char_val) & 0xFFFFFFFF)
                if verify == current_hash:
                    results.append((prev_hash, chr(char_val)))
                    break
    return results

def is_readable_char(c):
    """Check if character is likely part of readable text"""
    return c.isalnum() or c in '_{}- '

def is_readable_string(s):
    """Check if string looks readable"""
    if len(s) < 5:
        return False
    # Should have mostly alphanumeric or common punctuation
    readable_count = sum(1 for c in s if is_readable_char(c))
    return readable_count / len(s) > 0.7

def find_readable_flag(target_hash, initial_hash, max_depth=30):
    from collections import deque
    
    queue = deque([(target_hash, "")])
    visited = {}
    
    iteration = 0
    max_iterations = 5000000
    
    print(f"Searching for readable flag: 0x{target_hash:x} -> 0x{initial_hash:x}")
    print(f"Max depth: {max_depth}\n")
    
    best_readable = None
    best_score = 0
    
    while queue and iteration < max_iterations:
        iteration += 1
        
        current_hash, path = queue.popleft()
        path_len = len(path)
        
        if path_len > max_depth:
            continue
        
        if current_hash == initial_hash:
            if is_readable_string(path):
                return path
            # Track best readable even if not perfect
            score = sum(1 for c in path if is_readable_char(c))
            if score > best_score:
                best_score = score
                best_readable = path
        
        # Track visited
        state_key = (current_hash, path_len)
        if state_key in visited:
            continue
        visited[state_key] = True
        
        # Get all valid previous hashes
        prev_options = get_prev_hashes(current_hash)
        
        # Prioritize readable characters
        readable_options = [(h, c) for h, c in prev_options if is_readable_char(c) and h >= initial_hash]
        other_options = [(h, c) for h, c in prev_options if not is_readable_char(c) and h >= initial_hash]
        
        # Try readable first
        for prev_hash, char in readable_options[:10]:  # Limit to top 10 readable
            queue.append((prev_hash, char + path))
        
        # Also try some non-readable if needed
        for prev_hash, char in other_options[:3]:  # Limit to 3 non-readable
            queue.append((prev_hash, char + path))
        
        if iteration % 100000 == 0:
            print(f"  Iter {iteration}: queue={len(queue)}, path_len={path_len}, best_score={best_score}")
    
    return best_readable

target = 0x72d59e59
initial = 0x1505

print("=" * 70)
result = find_readable_flag(target, initial, max_depth=40)

if result:
    print(f"\n[+] FLAG: {result}")
    print(f"Verification: 0x{hash_string(result):08x} == 0x{target:08x}")
    if hash_string(result) == target:
        print("✓ CORRECT!")
    else:
        print("✗ Hash mismatch")
else:
    print("\n[-] No readable flag found")


