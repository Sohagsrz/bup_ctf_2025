#!/usr/bin/env python3
"""
Fast meet-in-the-middle approach
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

def get_next_hashes(current_hash):
    results = []
    for char_val in range(32, 127):
        next_hash = ((current_hash * 33 + char_val) & 0xFFFFFFFF)
        results.append((next_hash, chr(char_val)))
    return results

# Meet in the middle: build forward and backward sets
target = 0x72d59e59
initial = 0x1505

print("Fast meet-in-the-middle search")
print(f"Target: 0x{target:x}, Initial: 0x{initial:x}")
print()

# Build forward set (from initial)
print("Building forward set...")
forward = {initial: ""}
for depth in range(1, 15):  # Limit depth
    new_forward = {}
    for h, path in forward.items():
        if len(path) == depth - 1:
            for next_hash, char in get_next_hashes(h):
                if next_hash not in forward and next_hash not in new_forward:
                    new_forward[next_hash] = path + char
    forward.update(new_forward)
    print(f"  Depth {depth}: {len(forward)} hashes")

# Build backward set (from target)  
print("\nBuilding backward set...")
backward = {target: ""}
for depth in range(1, 15):
    new_backward = {}
    for h, path in backward.items():
        if len(path) == depth - 1:
            for prev_hash, char in get_prev_hashes(h):
                if prev_hash >= initial:
                    if prev_hash not in backward and prev_hash not in new_backward:
                        new_backward[prev_hash] = char + path
    backward.update(new_backward)
    print(f"  Depth {depth}: {len(backward)} hashes")
    
    # Check for intersection
    intersection = forward.keys() & backward.keys()
    if intersection:
        print(f"\n[+] FOUND INTERSECTION!")
        for common_hash in intersection:
            forward_path = forward[common_hash]
            backward_path = backward[common_hash]
            flag = forward_path + backward_path
            print(f"\n[+] FLAG: {flag}")
            print(f"Verification: 0x{hash_string(flag):08x} == 0x{target:08x}")
            if hash_string(flag) == target:
                print("✓ CORRECT!")
            break

if not intersection:
    print("\n[-] No intersection found - may need deeper search")


