#!/usr/bin/env python3
"""
Constrained hash reversal - assume flag format CS{...}
This reduces search space significantly
"""

def hash_string(s):
    hash_val = 0x1505
    for c in s:
        hash_val = ((hash_val << 5) + hash_val + ord(c)) & 0xFFFFFFFF
    return hash_val

# Pre-compute hash of "CS{"
prefix_hash = hash_string("CS{")
print(f"Hash of 'CS{{': 0x{prefix_hash:x}")

# Now we need to find suffix such that:
# hash("CS{" + suffix + "}") == 0x72d59e59
# This means: hash("CS{" + suffix) should lead to a value where adding "}" gives 0x72d59e59

# Work backwards from target
target = 0x72d59e59
# If flag ends with "}", then before "}" we had some hash value
# hash_final = (hash_before * 33 + ord('}')) mod 2^32 = 0x72d59e59
# hash_before = (0x72d59e59 - ord('}')) / 33

hash_before_close = ((target - ord('}')) % (2**32))
if hash_before_close % 33 == 0:
    hash_before_close = (hash_before_close // 33) & 0xFFFFFFFF
    print(f"Hash before '}}': 0x{hash_before_close:x}")
    
    # Now we need to find suffix such that hash("CS{" + suffix) == hash_before_close
    # We can work backwards from hash_before_close
    current = hash_before_close
    suffix = ""
    
    # Work backwards until we reach prefix_hash
    for i in range(50):
        if current == prefix_hash:
            break
        
        char_mod = current % 33
        found = False
        
        for char_val in range(32, 127):
            if char_val % 33 == char_mod:
                diff = (current - char_val) % (2**32)
                if diff % 33 == 0:
                    prev = (diff // 33) & 0xFFFFFFFF
                    verify = ((prev * 33 + char_val) & 0xFFFFFFFF)
                    if verify == current and prev >= prefix_hash:
                        suffix = chr(char_val) + suffix
                        current = prev
                        found = True
                        break
        
        if not found:
            print(f"Stopped at step {i}, hash: 0x{current:x}")
            break
    
    if current == prefix_hash:
        flag = "CS{" + suffix + "}"
        print(f"\n[+] FLAG: {flag}")
        print(f"[+] Verification: 0x{hash_string(flag):08x}")
        if hash_string(flag) == target:
            print("[+] CORRECT!")
    else:
        print(f"Could not complete. Current: 0x{current:x}, need: 0x{prefix_hash:x}")
else:
    print("Cannot work backwards from target (not divisible by 33)")

