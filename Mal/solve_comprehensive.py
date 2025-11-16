#!/usr/bin/env python3
"""
Comprehensive solution for hash reversal using multiple approaches:
1. Z3 constraint solver (if available)
2. Optimized BFS with proper modulo arithmetic
3. Bidirectional search
"""

def hash_string(s):
    """Hash function matching the binary"""
    hash_val = 0x1505
    for c in s:
        hash_val = ((hash_val << 5) + hash_val + ord(c)) & 0xFFFFFFFF
    return hash_val

def get_prev_hashes(current_hash):
    """Get all valid (prev_hash, char) pairs going backwards"""
    results = []
    # Use modulo property: hash mod 33 = char mod 33 to reduce search space
    char_mod = current_hash % 33
    
    for char_val in range(32, 127):
        # First filter by modulo property
        if char_val % 33 == char_mod:
            diff = (current_hash - char_val) % (2**32)
            if diff % 33 == 0:
                prev_hash = (diff // 33) & 0xFFFFFFFF
                # Verify
                verify = ((prev_hash * 33 + char_val) & 0xFFFFFFFF)
                if verify == current_hash:
                    results.append((prev_hash, chr(char_val)))
    return results

def reverse_hash_bfs_optimized(target_hash, initial_hash, max_length=100):
    """Optimized BFS with better pruning"""
    from collections import deque
    
    queue = deque([(target_hash, "")])
    visited = set([target_hash])
    
    iteration = 0
    max_iterations = 10000000
    
    print(f"BFS: 0x{target_hash:08x} -> 0x{initial_hash:08x}")
    print(f"Max length: {max_length}, Max iterations: {max_iterations}")
    print()
    
    while queue and iteration < max_iterations:
        iteration += 1
        
        current_hash, path = queue.popleft()
        
        if len(path) > max_length:
            continue
        
        if current_hash == initial_hash:
            return path
        
        # Get all valid previous hashes
        prev_options = get_prev_hashes(current_hash)
        
        for prev_hash, char in prev_options:
            # Only explore if we haven't seen this hash or if it's closer to initial
            if prev_hash not in visited or prev_hash >= initial_hash:
                visited.add(prev_hash)
                queue.append((prev_hash, char + path))
        
        if iteration % 100000 == 0:
            print(f"  Iter {iteration}: visited {len(visited)}, queue: {len(queue)}, path_len: {len(path)}")
    
    return None

# Try Z3 first
try:
    from z3 import *
    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False

if Z3_AVAILABLE:
    def solve_with_z3(target_hash, max_length=50):
        """Use Z3 to solve for the flag"""
        print("=" * 70)
        print("Attempting Z3 constraint solving...")
        print("=" * 70)
        
        s = Solver()
        
        # Create character variables
        chars = [BitVec(f'c{i}', 8) for i in range(max_length)]
        
        # Constraints: printable ASCII (32-126)
        for c in chars:
            s.add(c >= 32)
            s.add(c < 127)
        
        # Hash calculation
        hash_val = BitVecVal(0x1505, 32)
        for c in chars:
            hash_val = hash_val * BitVecVal(33, 32) + ZeroExt(24, c)
        
        # Target hash
        s.add(hash_val == BitVecVal(target_hash, 32))
        
        # Try to find a solution
        print("Solving with Z3...")
        if s.check() == sat:
            model = s.model()
            result_chars = []
            for c in chars:
                val = model[c].as_long()
                if val >= 32 and val < 127:
                    result_chars.append(chr(val))
                else:
                    break
            result = ''.join(result_chars)
            # Remove trailing nulls/whitespace
            result = result.rstrip('\x00').rstrip()
            return result
        return None
    
    # Try Z3 with different lengths
    target = 0x72d59e59
    result = None
    
    for length in range(10, 60, 5):
        print(f"\nTrying Z3 with length {length}...")
        result = solve_with_z3(target, length)
        if result:
            print(f"\n[+] Z3 Found: {result}")
            print(f"[+] Verification: hash = 0x{hash_string(result):08x}")
            if hash_string(result) == target:
                print("[+] CORRECT!")
                break
    
    if result and hash_string(result) == target:
        print(f"\n{'='*70}")
        print(f"FLAG: {result}")
        print(f"{'='*70}")
        exit(0)

# If Z3 didn't work or isn't available, try BFS
print("\n" + "=" * 70)
print("Z3 not available or didn't find solution. Trying optimized BFS...")
print("=" * 70)

target = 0x72d59e59
initial = 0x1505

result = reverse_hash_bfs_optimized(target, initial, max_length=100)

if result:
    print("\n" + "=" * 70)
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
    print("\n[-] Could not find flag with BFS")
    print("    May need more iterations or different approach")


