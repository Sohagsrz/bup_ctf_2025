#!/usr/bin/env python3
"""
Try ALL valid paths, not just first match
"""

def hash_string(s):
    hash_val = 0x1505
    for c in s:
        hash_val = ((hash_val << 5) + hash_val + ord(c)) & 0xFFFFFFFF
    return hash_val

def find_prev_hash(current_hash, char_val):
    diff = (current_hash - char_val) % (2**32)
    if diff % 33 == 0:
        prev = (diff // 33) & 0xFFFFFFFF
        verify = ((prev * 33 + char_val) & 0xFFFFFFFF)
        if verify == current_hash:
            return prev
    return None

# BFS exploring ALL paths
from collections import deque

target = 0x72d59e59
initial = 0x1505

queue = deque([(target, "")])
visited = {target}
max_depth = 60

print("Exploring all paths with BFS...")

while queue:
    current_hash, path = queue.popleft()
    
    if len(path) > max_depth:
        continue
    
    if current_hash == initial:
        print(f"\n[+] FLAG FOUND: {path}")
        print(f"[+] Verification: 0x{hash_string(path):08x}")
        if hash_string(path) == target:
            print("[+] CORRECT!")
        break
    
    # Try ALL valid characters
    for char_val in range(32, 127):
        prev = find_prev_hash(current_hash, char_val)
        if prev is not None and prev >= initial:
            if prev not in visited:
                visited.add(prev)
                queue.append((prev, chr(char_val) + path))
    
    if len(visited) % 10000 == 0:
        print(f"  Visited {len(visited)} states, queue: {len(queue)}, path length: {len(path)}")

if current_hash != initial:
    print("Could not find path")

