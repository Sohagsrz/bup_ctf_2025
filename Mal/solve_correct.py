#!/usr/bin/env python3
"""
Correct hash reversal with proper modulo arithmetic
"""

def hash_string(s):
    hash_val = 0x1505
    for c in s:
        hash_val = ((hash_val << 5) + hash_val + ord(c)) & 0xFFFFFFFF
    return hash_val

def get_prev_hashes_correct(current_hash):
    """Correct reverse: handle all possible k values in modulo arithmetic"""
    results = []
    
    for char_val in range(32, 127):
        diff = (current_hash - char_val) % (2**32)
        
        # We need: prev * 33 = diff + k * 2^32 for some integer k
        # Try different k values (0 to 32 should be enough)
        for k in range(33):
            candidate = diff + k * (2**32)
            if candidate % 33 == 0:
                prev_hash = (candidate // 33) & 0xFFFFFFFF
                # Verify
                verify = ((prev_hash * 33 + char_val) & 0xFFFFFFFF)
                if verify == current_hash:
                    results.append((prev_hash, chr(char_val)))
                    break  # Found one solution for this char
    
    return results

def exhaustive_search_correct(target_hash, initial_hash, max_depth=50):
    from collections import deque
    
    queue = deque([(target_hash, "")])
    visited = {}  # hash -> set of path_lengths
    
    iteration = 0
    max_iterations = 100000000
    
    print(f"Correct exhaustive search: 0x{target_hash:x} -> 0x{initial_hash:x}")
    print(f"Max depth: {max_depth}")
    print()
    
    while queue:
        iteration += 1
        
        if iteration > max_iterations:
            print(f"\nReached limit: {max_iterations}")
            print(f"Visited: {len(visited)} states")
            break
        
        current_hash, path = queue.popleft()
        path_len = len(path)
        
        if path_len > max_depth:
            continue
        
        if current_hash == initial_hash:
            return path
        
        # Track visited
        if current_hash not in visited:
            visited[current_hash] = set()
        if path_len in visited[current_hash]:
            continue
        visited[current_hash].add(path_len)
        
        # Get ALL valid previous hashes (now correctly finding all 95 possibilities)
        prev_options = get_prev_hashes_correct(current_hash)
        
        for prev_hash, char in prev_options:
            if prev_hash >= initial_hash:
                queue.append((prev_hash, char + path))
        
        if iteration % 1000000 == 0:
            print(f"  Iter {iteration}: visited {len(visited)}, queue {len(queue)}, path_len {path_len}")
    
    return None

target = 0x72d59e59
initial = 0x1505

print("=" * 70)
print("CORRECT Hash Reversal")
print("=" * 70)
print()

# Test the correct algorithm first
test = "ABCD"
test_hash = hash_string(test)
print(f"Test: hash('{test}') = 0x{test_hash:08x}")
options = get_prev_hashes_correct(test_hash)
print(f"Found {len(options)} valid previous hashes (should be ~95)")
expected_prev = hash_string("ABC")
found = any(h == expected_prev and c == 'D' for h, c in options)
print(f"Contains correct reverse: {found}")
print()

# Now solve the actual problem
result = exhaustive_search_correct(target, initial, max_depth=50)

if result:
    print(f"\n[+] FLAG: {result}")
    print(f"Verification: 0x{hash_string(result):08x} == 0x{target:08x}")
    if hash_string(result) == target:
        print("✓ CORRECT!")
else:
    print("\n[-] Not found - may need more depth or iterations")

