#!/usr/bin/env python3
"""
Find the flag by testing all hash functions with systematic inputs
"""

from all_hashes import orbit_mist, orbit_ember, orbit_tide, orbit_quartz, orbit_haze, orbit_nova
import string
import itertools

# Expected values
EXPECTED_HASHES = [
    0x49ec606db1d2e62d,
    0x2ab1ab1ec269421e,
    0xe49a159a174cbcf8,
    0x47f34a499b2edd93,
    0x237a429b80010643
]

FINAL_CHECK = 0xFCE62D194453D523
XOR_KEY = 0xC3B1E37F9A4D2605

# Based on analysis: lanes[0]=1 (orbit_ember), lanes[1]=?, lanes[2/3]=0 (orbit_mist)
# Let's test all functions with all expected values
FUNCTIONS = [
    ('orbit_mist', orbit_mist),
    ('orbit_ember', orbit_ember),
    ('orbit_tide', orbit_tide),
    ('orbit_quartz', orbit_quartz),
    ('orbit_haze', orbit_haze),
    ('orbit_nova', orbit_nova),
]

def test_candidates():
    """Test various flag candidates"""
    candidates = [
        b'CS{something_her3}',
        b'CS{R3_M3}',
        b'CS{r3_m3}',
        b'CS{R3M3}',
        b'CS{r3m3}',
        b'CS{reverse_me}',
        b'CS{reverse_her3}',
        b'CS{her3_something}',
        b'CS{flag_her3}',
        b'CS{challenge_her3}',
    ]
    
    print("=== Testing Candidates ===")
    for candidate in candidates:
        test_bytes = candidate
        length = len(test_bytes)
        
        for func_name, func in FUNCTIONS:
            try:
                hash_val = func(test_bytes, length)
                if hash_val in EXPECTED_HASHES:
                    idx = EXPECTED_HASHES.index(hash_val)
                    print(f"✓ MATCH: {candidate.decode()} with {func_name}")
                    print(f"  Hash: 0x{hash_val:016x} matches expected[{idx}]")
                    return candidate.decode()
                if func_name == 'orbit_nova' and hash_val == FINAL_CHECK:
                    print(f"✓ MATCH: {candidate.decode()} with {func_name} (FINAL)")
                    print(f"  Hash: 0x{hash_val:016x} matches final check")
                    return candidate.decode()
            except Exception as e:
                pass
    
    return None

def brute_force_short():
    """Brute force short flags"""
    print("\n=== Brute Force Short Flags ===")
    charset = string.ascii_lowercase + string.digits + '_'
    
    # Try lengths 3-12
    for length in range(3, 13):
        print(f"Trying length {length}...")
        count = 0
        max_tests = 500000  # Limit per length
        
        for combo in itertools.product(charset, repeat=length):
            if count >= max_tests:
                break
            
            test_str = f"CS{{{' '.join(combo)}}}"
            test_bytes = test_str.encode()
            
            # Test all functions
            for func_name, func in FUNCTIONS:
                try:
                    hash_val = func(test_bytes, len(test_bytes))
                    if hash_val in EXPECTED_HASHES:
                        print(f"✓ FOUND: {test_str}")
                        print(f"  Function: {func_name}, Hash: 0x{hash_val:016x}")
                        return test_str
                    if func_name == 'orbit_nova' and hash_val == FINAL_CHECK:
                        print(f"✓ FOUND: {test_str}")
                        print(f"  Function: {func_name}, Hash: 0x{hash_val:016x}")
                        return test_str
                except:
                    pass
            
            count += 1
            if count % 50000 == 0:
                print(f"  Tested {count} combinations...")
    
    return None

def try_specific_patterns():
    """Try specific patterns based on hints"""
    print("\n=== Trying Specific Patterns ===")
    
    # The hint says "something_her3"
    # Challenge name is "R3 M3"
    # Let's try combinations
    
    patterns = [
        # Direct variations
        'something_her3',
        'R3_M3_her3',
        'r3_m3_her3',
        'R3M3_her3',
        'r3m3_her3',
        # With different separators
        'something-her3',
        'R3-M3-her3',
        # Reversed
        'her3_something',
        'her3_R3_M3',
        # Other combinations
        'reverse_her3',
        'flag_her3',
        'challenge_her3',
        'ctf_her3',
        # Just the hint parts
        'her3',
        'R3_M3',
        # With numbers
        'R3_M3_her3!',
        'R3_M3_her3_',
    ]
    
    for pattern in patterns:
        test_str = f"CS{{{pattern}}}"
        test_bytes = test_str.encode()
        
        for func_name, func in FUNCTIONS:
            try:
                hash_val = func(test_bytes, len(test_bytes))
                if hash_val in EXPECTED_HASHES:
                    print(f"✓ MATCH: {test_str} with {func_name}")
                    return test_str
                if func_name == 'orbit_nova' and hash_val == FINAL_CHECK:
                    print(f"✓ MATCH: {test_str} with {func_name} (FINAL)")
                    return test_str
            except:
                pass
    
    return None

if __name__ == '__main__':
    print("=== Finding the Flag ===")
    
    # Try candidates first
    flag = test_candidates()
    if flag:
        print(f"\n🎉 FLAG FOUND: {flag}")
        exit(0)
    
    # Try specific patterns
    flag = try_specific_patterns()
    if flag:
        print(f"\n🎉 FLAG FOUND: {flag}")
        exit(0)
    
    # Try brute force
    flag = brute_force_short()
    if flag:
        print(f"\n🎉 FLAG FOUND: {flag}")
        exit(0)
    
    print("\n❌ Flag not found with current approaches")


