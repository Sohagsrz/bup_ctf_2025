#!/usr/bin/env python3
"""
Final solver: Try all combinations and use z3 if needed
"""

from z3 import *
import sys
import os

# Add the current directory to path to import our hash functions
sys.path.insert(0, os.path.dirname(__file__))

# Import hash functions
from implement_hashes import orbit_mist, orbit_ember, rol64, ror64

# Constants
EXPECTED_HASHES = [
    0x49ec606db1d2e62d,
    0x2ab1ab1ec269421e,
    0xe49a159a174cbcf8,
    0x47f34a499b2edd93,
    0x237a429b80010643
]

FINAL_CHECK = 0xFCE62D194453D523

def try_brute_force():
    """Try brute forcing with common patterns"""
    import string
    import itertools
    
    print("=== Brute Force Approach ===")
    print("Trying common flag patterns...")
    
    # Common words that might be in the flag
    common_words = [
        "flag", "test", "reverse", "me", "r3", "m3", "r3m3", 
        "something", "her3", "here", "challenge", "ctf"
    ]
    
    # Try combinations
    for word1 in common_words:
        for word2 in common_words:
            if word1 == word2:
                continue
            test_str = f"CS{{{word1}_{word2}}}"
            test_bytes = test_str.encode()
            
            # Test with orbit_mist
            hash_val = orbit_mist(test_bytes, len(test_bytes))
            if hash_val in EXPECTED_HASHES:
                idx = EXPECTED_HASHES.index(hash_val)
                print(f"✓ Found match with orbit_mist!")
                print(f"  Input: {test_str}")
                print(f"  Hash: 0x{hash_val:016x}")
                print(f"  Matches expected[{idx}]")
                return test_str
            
            # Test with orbit_ember
            hash_val = orbit_ember(test_bytes, len(test_bytes))
            if hash_val in EXPECTED_HASHES:
                idx = EXPECTED_HASHES.index(hash_val)
                print(f"✓ Found match with orbit_ember!")
                print(f"  Input: {test_str}")
                print(f"  Hash: 0x{hash_val:016x}")
                print(f"  Matches expected[{idx}]")
                return test_str
    
    print("No matches found with common patterns")
    return None

def try_with_z3():
    """Try using z3 to solve for the flag"""
    print("\n=== Z3 Solver Approach ===")
    print("Setting up constraints...")
    
    # Create symbolic variables for flag
    flag_length = 30
    flag_chars = [BitVec(f'flag_{i}', 8) for i in range(flag_length)]
    
    solver = Solver()
    
    # Constraints: flag format CS{...}
    solver.add(flag_chars[0] == ord('C'))
    solver.add(flag_chars[1] == ord('S'))
    solver.add(flag_chars[2] == ord('{'))
    
    # Find closing brace
    has_closing = False
    for i in range(3, flag_length):
        # Either printable ASCII, closing brace, or null
        solver.add(Or(
            And(flag_chars[i] >= 32, flag_chars[i] <= 126),
            flag_chars[i] == ord('}'),
            flag_chars[i] == 0
        ))
        if not has_closing:
            # If we find a closing brace, everything after should be null
            for j in range(i+1, flag_length):
                solver.add(Implies(flag_chars[i] == ord('}'), flag_chars[j] == 0))
            has_closing = True
    
    # This is complex - implementing hash functions in z3 is difficult
    # Let's try a simpler approach first
    
    print("Z3 approach is complex - trying brute force first")
    return None

def main():
    print("=== Final Solver for R3 M3 ===")
    
    # Try brute force first
    result = try_brute_force()
    if result:
        print(f"\n🎉 FLAG FOUND: {result}")
        return result
    
    # Try z3 if brute force fails
    result = try_with_z3()
    if result:
        print(f"\n🎉 FLAG FOUND: {result}")
        return result
    
    print("\n❌ Flag not found with current approaches")
    print("May need to:")
    print("1. Complete all hash function implementations")
    print("2. Understand lanes array mapping")
    print("3. Use more advanced symbolic execution")

if __name__ == '__main__':
    main()


