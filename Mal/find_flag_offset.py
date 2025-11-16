#!/usr/bin/env python3
"""
Find the flag using offset-based approach.
The binary uses "increased size offset style" - maybe the flag is at a specific offset.
"""

import os
import re

def hash_string(s):
    """Hash function matching the binary"""
    hash_val = 0x1505
    for c in s:
        hash_val = ((hash_val << 5) + hash_val + ord(c)) & 0xFFFFFFFF
    return hash_val

def check_offset(offset, file_path='mal.ks'):
    """Check data at a specific offset"""
    with open(file_path, 'rb') as f:
        f.seek(offset)
        data = f.read(500)
        return data

# Try different offset calculations
hash_val = 0x72d59e59
file_size = os.path.getsize('mal.ks')

print(f"Hash: 0x{hash_val:x} ({hash_val})")
print(f"File size: {file_size} bytes ({file_size/1024/1024:.2f} MB)")
print()

# Try various offset calculations
offsets_to_try = [
    ("hash % file_size", hash_val % file_size),
    ("hash & 0xFFFFFF", hash_val & 0xFFFFFF),
    ("hash & 0xFFFFF", hash_val & 0xFFFFF),
    ("hash >> 8", hash_val >> 8),
    ("hash >> 16", hash_val >> 16),
    ("(hash >> 8) % file_size", (hash_val >> 8) % file_size),
    ("(hash >> 16) % file_size", (hash_val >> 16) % file_size),
]

for name, offset in offsets_to_try:
    if offset >= file_size:
        continue
    print(f"Trying {name}: offset 0x{offset:x} ({offset})")
    try:
        data = check_offset(offset)
        # Look for flag-like patterns
        text = data.decode('utf-8', errors='ignore')
        if 'CS{' in text or 'flag' in text.lower():
            print(f"  [*] Found potential flag data!")
            print(f"  {text[:200]}")
        # Also check for printable strings
        printable = ''.join(c if 32 <= ord(c) < 127 else '' for c in text[:100])
        if len(printable) > 20:
            print(f"  Printable: {printable[:80]}...")
    except Exception as e:
        print(f"  Error: {e}")
    print()

# Also search the entire file for flag patterns
print("Searching entire file for CS{...} patterns...")
with open('mal.ks', 'rb') as f:
    chunk_size = 1024 * 1024  # 1MB chunks
    offset = 0
    while True:
        chunk = f.read(chunk_size)
        if not chunk:
            break
        # Look for CS{ pattern
        matches = re.findall(b'CS\{[A-Za-z0-9_\-]+\}', chunk)
        if matches:
            for match in matches:
                print(f"  Found at offset ~{offset}: {match.decode('utf-8', errors='ignore')}")
        offset += chunk_size
        if offset % (100 * 1024 * 1024) == 0:
            print(f"  Searched {offset/1024/1024:.0f} MB...")

