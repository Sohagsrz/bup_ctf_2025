#!/usr/bin/env python3
"""
Reverse the hash algorithm to find the flag.

The hash algorithm from the binary:
- Start with hash = 0x1505
- For each character: hash = (hash << 5) + hash + char = hash * 33 + char
- Target hash: 0x72d59e59
"""

def hash_string(s):
    """Hash function matching the binary"""
    hash_val = 0x1505
    for c in s:
        hash_val = ((hash_val << 5) + hash_val + ord(c)) & 0xFFFFFFFF
    return hash_val

def reverse_hash_backwards(target_hash, max_length=50):
    """
    Work backwards from target hash to find the input string.
    If hash = prev_hash * 33 + char, then:
    prev_hash = (hash - char) / 33
    We need to find valid characters that make prev_hash valid.
    """
    target = target_hash & 0xFFFFFFFF
    
    # Try different lengths
    for length in range(10, max_length + 1):
        print(f"Trying length {length}...")
        
        # Work backwards
        current_hash = target
        result = []
        
        for i in range(length):
            found_char = None
            
            # Try all printable ASCII characters
            for char_val in range(32, 127):
                # Calculate previous hash
                # current_hash = prev_hash * 33 + char_val
                # prev_hash = (current_hash - char_val) / 33
                diff = (current_hash - char_val) % (2**32)
                
                # Check if divisible by 33
                if diff % 33 == 0:
                    prev_hash = diff // 33
                    prev_hash = prev_hash & 0xFFFFFFFF
                    
                    # Check if this is a valid previous hash
                    # It should be >= 0x1505 (initial hash) or we're at the start
                    if i == length - 1:
                        # Last iteration, should equal initial hash
                        if prev_hash == 0x1505:
                            result.insert(0, chr(char_val))
                            current_hash = prev_hash
                            found_char = chr(char_val)
                            break
                    else:
                        # Intermediate step, just needs to be reasonable
                        if prev_hash >= 0x1505:
                            result.insert(0, chr(char_val))
                            current_hash = prev_hash
                            found_char = chr(char_val)
                            break
            
            if found_char is None:
                break
        
        # Check if we found a valid string
        if len(result) == length and current_hash == 0x1505:
            candidate = ''.join(result)
            # Verify
            if hash_string(candidate) == target:
                return candidate
    
    return None

def brute_force_with_pattern(target_hash):
    """Brute force with common flag patterns"""
    target = target_hash & 0xFFFFFFFF
    
    # Common patterns
    patterns = [
        "CS{" + "A" * 20 + "}",
        "CS{fl4g_here}",
        "CS{reverse_me}",
        "CS{mal_ware}",
    ]
    
    # Try variations
    import string
    charset = string.ascii_letters + string.digits + "_"
    
    # Try CS{...} format
    for prefix_len in range(3, 20):
        for suffix_len in range(1, 10):
            # This would be too slow, let's try a smarter approach
            pass
    
    return None

# Main execution
print("Attempting to reverse hash 0x72d59e59...")
print("Hash algorithm: hash = hash * 33 + char, starting from 0x1505")
print()

result = reverse_hash_backwards(0x72d59e59, max_length=60)

if result:
    print(f"\n[+] Found flag: {result}")
    print(f"[+] Verification: hash({result}) = 0x{hash_string(result):08x}")
    print(f"[+] Target hash: 0x72d59e59")
    if hash_string(result) == 0x72d59e59:
        print("[+] Hash matches! This is the correct flag!")
    else:
        print("[!] Hash doesn't match, but this might be close")
else:
    print("[-] Could not reverse hash directly")
    print("Trying brute force with common patterns...")
    
    # Try some common flag strings
    test_strings = [
        "CS{reverse_me}",
        "CS{mal_ware}",
        "CS{hash_me}",
        "CS{flag_here}",
        "CS{fl4g_here}",
    ]
    
    for test in test_strings:
        h = hash_string(test)
        print(f"hash('{test}') = 0x{h:08x}")
        if h == 0x72d59e59:
            print(f"[+] Found: {test}")
            break
