#!/usr/bin/env python3
"""Greedy: keep only best path at each step"""
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

target, initial = 0x72d59e59, 0x1505
current, path = target, ""

for _ in range(100):
    if current == initial:
        print(path if hash_string(path) == target else "Mismatch")
        break
    opts = get_prev_hashes(current)
    if not opts: break
    # Pick closest to initial
    best = min(opts, key=lambda x: x[0] - initial if x[0] >= initial else float('inf'))
    if best[0] < initial: break
    current, path = best[0], best[1] + path
    print(f"Step {_}: char='{best[1]}', hash=0x{current:x}, dist={current-initial}")

if current != initial:
    print(f"Stopped: 0x{current:x} != 0x{initial:x}")


