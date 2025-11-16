#!/usr/bin/env python3
"""
Quick solve - try common CTF flag patterns
"""

def hash_string(s):
    hash_val = 0x1505
    for c in s:
        hash_val = ((hash_val << 5) + hash_val + ord(c)) & 0xFFFFFFFF
    return hash_val

target = 0x72d59e59

# Common CTF flag patterns to try
common_flags = [
    "CS{reverse_me}",
    "CS{hash_me}",
    "CS{malware}",
    "CS{mal_ware}",
    "CS{djb2_hash}",
    "CS{hash_reverse}",
    "CS{fl4g_here}",
    "CS{flag_here}",
    "CS{the_flag}",
    "CS{reverse_hash}",
    "CS{0x72d59e59}",
    "CS{72d59e59}",
    "CS{1505}",
]

print("Trying common flag patterns...")
for flag in common_flags:
    h = hash_string(flag)
    match = "✓" if h == target else "✗"
    print(f"{flag:25} -> 0x{h:08x} {match}")

# Also try the solution we found
found = "CS{O|5X|2}"
print(f"\nOur found solution: {found}")
h = hash_string(found)
print(f"Hash: 0x{h:08x} {'✓' if h == target else '✗'}")

print(f"\nTarget: 0x{target:08x}")


