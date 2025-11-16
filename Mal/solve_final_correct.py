#!/usr/bin/env python3
"""
Correct hash reversal handling modulo arithmetic properly
"""

def hash_string(s):
    hash_val = 0x1505
    for c in s:
        hash_val = ((hash_val << 5) + hash_val + ord(c)) & 0xFFFFFFFF
    return hash_val

def find_prev_hash(current_hash, char_val):
    """Find previous hash such that (prev * 33 + char) mod 2^32 == current"""
    # We need: (prev * 33 + char) mod 2^32 == current
    # This means: prev * 33 ≡ (current - char) (mod 2^32)
    # Since 33 and 2^32 are coprime, we can solve this
    
    diff = (current_hash - char_val) % (2**32)
    
    # Check if divisible by 33
    if diff % 33 == 0:
        prev = (diff // 33) & 0xFFFFFFFF
        # Verify
        verify = ((prev * 33 + char_val) & 0xFFFFFFFF)
        if verify == current_hash:
            return prev
    return None

# Work backwards from target
target = 0x72d59e59
initial = 0x1505

# Try working backwards character by character
result = []
current = target
max_steps = 100

for step in range(max_steps):
    if current == initial:
        break
    
    # Try all characters
    found = False
    for char_val in range(32, 127):
        prev = find_prev_hash(current, char_val)
        if prev is not None and prev >= initial:
            result.insert(0, chr(char_val))
            current = prev
            found = True
            break
    
    if not found:
        # Try with modulo property: current mod 33 = char mod 33
        char_mod = current % 33
        for char_val in range(32, 127):
            if char_val % 33 == char_mod:
                prev = find_prev_hash(current, char_val)
                if prev is not None and prev >= initial:
                    result.insert(0, chr(char_val))
                    current = prev
                    found = True
                    break
    
    if not found:
        print(f"Stopped at step {step}, hash: 0x{current:x}")
        break

if current == initial:
    flag = ''.join(result)
    print(f"\n[+] FLAG: {flag}")
    print(f"[+] Verification: 0x{hash_string(flag):08x} == 0x{target:x}")
    if hash_string(flag) == target:
        print("[+] CORRECT!")
else:
    print(f"Could not complete. Current: 0x{current:x}, need: 0x{initial:x}")
    print(f"Partial result: {''.join(result)}")

