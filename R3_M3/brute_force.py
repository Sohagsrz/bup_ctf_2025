#!/usr/bin/env python3
"""
Brute force approach to find the flag
"""

import string
import itertools

# The expected hash values (XORed drift_table entries)
EXPECTED_HASHES = [
    0x49ec606db1d2e62d,
    0x2ab1ab1ec269421e,
    0xe49a159a174cbcf8,
    0x47f34a499b2edd93,
    0x237a429b80010643
]

FINAL_CHECK = 0xFCE62D194453D523

def orbit_mist_simple(input_str, length):
    """Simplified orbit_mist for testing"""
    # This is a complex hash - for now, let's try to find patterns
    if length == 0:
        return 0x9E3779B185EBCA87
    
    # Simplified version - will need full implementation
    hash_val = 0
    for i, c in enumerate(input_str):
        hash_val = ((hash_val * 0x9e3779b1) + c + i) & 0xFFFFFFFFFFFFFFFF
        hash_val = ((hash_val << (i % 8 + 1)) | (hash_val >> (64 - (i % 8 + 1)))) & 0xFFFFFFFFFFFFFFFF
    
    return hash_val

def try_flag_format():
    """Try common flag formats"""
    # Flag format: CS{something_her3}
    prefix = "CS{"
    suffix = "}"
    
    # Try different lengths and characters
    charset = string.ascii_letters + string.digits + "_"
    
    print("Trying flag format CS{...}")
    print("This might take a while...")
    
    # Try short flags first
    for length in range(5, 30):
        print(f"\nTrying length {length}...")
        middle_len = length - 4  # CS{...}
        
        # Try a limited search space
        count = 0
        for combo in itertools.product(charset, repeat=min(middle_len, 6)):
            if count > 10000:  # Limit per length
                break
            test_str = prefix + ''.join(combo) + suffix
            test_bytes = test_str.encode()
            
            # Test with orbit_mist
            hash_val = orbit_mist_simple(test_bytes, len(test_bytes))
            if hash_val in EXPECTED_HASHES:
                print(f"Possible match: {test_str} -> 0x{hash_val:016x}")
            
            count += 1

if __name__ == '__main__':
    try_flag_format()


