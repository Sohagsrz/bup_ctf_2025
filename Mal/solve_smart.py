#!/usr/bin/env python3
"""
Smart backward search prioritizing readable characters
"""

def hash_string(s):
    h = 0x1505
    for c in s:
        h = ((h << 5) + h + ord(c)) & 0xFFFFFFFF
    return h

def get_prev_hashes(h):
    results = []
    for c in range(32, 127):
        d = (h - c) % (2**32)
        for k in range(33):
            if (d + k * (2**32)) % 33 == 0:
                p = ((d + k * (2**32)) // 33) & 0xFFFFFFFF
                if ((p * 33 + c) & 0xFFFFFFFF) == h:
                    results.append((p, chr(c)))
                    break
    return results

def is_readable(c):
    return c.isalnum() or c in '_{}- '

target, initial = 0x72d59e59, 0x1505

# Use a priority queue: prioritize readable characters and shorter distances
from heapq import heappush, heappop

queue = [(0, target, "")]
visited = {}
max_depth = 50

print("Smart search for readable flag...")
print(f"Target: 0x{target:x} -> Initial: 0x{initial:x}\n")

iteration = 0
while queue and iteration < 2000000:
    iteration += 1
    priority, current, path = heappop(queue)
    
    if len(path) > max_depth:
        continue
    
    if current == initial:
        print(f"\n[+] FLAG FOUND: {path}")
        print(f"[+] Length: {len(path)} chars")
        print(f"[+] Verification: 0x{hash_string(path):08x}")
        if hash_string(path) == target:
            print("[+] ✓ CORRECT!")
        break
    
    state = (current, len(path))
    if state in visited:
        continue
    visited[state] = True
    
    options = get_prev_hashes(current)
    
    # Separate readable and non-readable
    readable = [(h, c) for h, c in options if is_readable(c) and h >= initial]
    others = [(h, c) for h, c in options if not is_readable(c) and h >= initial]
    
    # Prioritize readable, then by distance to initial
    for h, c in readable[:20]:  # Top 20 readable
        dist = h - initial
        # Lower priority = better (readable gets negative boost)
        p = dist + len(path) - 1000  # Boost readable paths
        heappush(queue, (p, h, c + path))
    
    # Also try some non-readable but close
    for h, c in sorted(others, key=lambda x: x[0] - initial)[:5]:
        dist = h - initial
        p = dist + len(path) + 5000  # Lower priority
        heappush(queue, (p, h, c + path))
    
    if iteration % 50000 == 0:
        print(f"  Iter {iteration}: queue={len(queue)}, path_len={len(path)}, hash=0x{current:x}")

if current != initial:
    print(f"\n[-] Not found. Stopped at: 0x{current:x}")


