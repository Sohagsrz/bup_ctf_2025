#!/usr/bin/env python3
"""
Proper hash reversal using BFS with correct modulo arithmetic
"""

def hash_string(s):
    """Hash function matching the binary"""
    hash_val = 0x1505
    for c in s:
        hash_val = ((hash_val << 5) + hash_val + ord(c)) & 0xFFFFFFFF
    return hash_val

def get_prev_hashes(current_hash):
    """
    Find all valid (prev_hash, char) pairs such that:
    (prev_hash * 33 + char) mod 2^32 == current_hash
    """
    results = []
    
    for char_val in range(32, 127):  # Printable ASCII
        # We need: (prev * 33 + char) mod 2^32 == current
        # This means: prev * 33 ≡ (current - char) (mod 2^32)
        
        # Calculate: diff = (current - char) mod 2^32
        diff = (current_hash - char_val) % (2**32)
        
        # Check if divisible by 33
        if diff % 33 == 0:
            prev_hash = (diff // 33) & 0xFFFFFFFF
            
            # Verify: (prev * 33 + char) mod 2^32 == current
            verify = ((prev_hash * 33 + char_val) & 0xFFFFFFFF)
            if verify == current_hash:
                results.append((prev_hash, chr(char_val)))
    
    return results

def reverse_hash_bfs(target_hash, initial_hash, max_length=100):
    """BFS to find path from target to initial"""
    from collections import deque
    
    queue = deque([(target_hash, "")])
    visited = {target_hash}
    
    iteration = 0
    max_iterations = 1000000  # Increase limit
    
    print(f"Starting BFS from 0x{target_hash:x} to 0x{initial_hash:x}")
    print("This may take a while...")
    
    while queue:
        iteration += 1
        
        if iteration > max_iterations:
            print(f"Reached iteration limit ({max_iterations})")
            break
        
        current_hash, path = queue.popleft()
        
        if len(path) > max_length:
            continue
        
        if current_hash == initial_hash:
            return path
        
        # Get all valid previous hashes
        prev_options = get_prev_hashes(current_hash)
        
        for prev_hash, char in prev_options:
            # Only explore if prev_hash >= initial_hash (we're going backwards)
            if prev_hash >= initial_hash and prev_hash not in visited:
                visited.add(prev_hash)
                queue.append((prev_hash, char + path))
        
        if iteration % 50000 == 0:
            print(f"  Iteration {iteration}: visited {len(visited)} states, queue size: {len(queue)}, current path length: {len(path)}")
    
    return None

# Main execution
target = 0x72d59e59
initial = 0x1505

print("=" * 60)
print("Hash Reversal Challenge")
print("=" * 60)
print(f"Target hash: 0x{target:x}")
print(f"Initial hash: 0x{initial:x}")
print(f"Algorithm: hash = (hash * 33 + char) mod 2^32")
print("=" * 60)
print()

result = reverse_hash_bfs(target, initial, max_length=100)

if result:
    print()
    print("=" * 60)
    print(f"[+] FLAG FOUND: {result}")
    print("=" * 60)
    print(f"Verification:")
    print(f"  Hash of flag: 0x{hash_string(result):08x}")
    print(f"  Target hash:  0x{target:08x}")
    
    if hash_string(result) == target:
        print("  ✓ HASH MATCHES! This is the correct flag!")
    else:
        print("  ✗ Hash doesn't match - there may be an issue")
else:
    print()
    print("[-] Could not find flag")
    print("    This may require:")
    print("    - More iterations")
    print("    - Different approach")
    print("    - Or the flag might be longer than expected")

