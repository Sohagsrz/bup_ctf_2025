#!/usr/bin/env python3
"""
Comprehensive solver: Try all hash functions with systematic input generation
"""

import string
import itertools
from implement_hashes import orbit_mist, orbit_ember
from orbit_nova_complete import orbit_nova

# Expected values
EXPECTED_HASHES = [
    0x49ec606db1d2e62d,
    0x2ab1ab1ec269421e,
    0xe49a159a174cbcf8,
    0x47f34a499b2edd93,
    0x237a429b80010643
]

FINAL_CHECK = 0xFCE62D194453D523

# Based on analysis: lanes[0]=1 -> orbit_ember, lanes[2/3]=0 -> orbit_mist
# So we need to find inputs that hash to expected[0] with orbit_ember
# and inputs that hash to expected[2] or expected[3] with orbit_mist

def generate_flag_candidates():
    """Generate flag candidates systematically"""
    # Flag format: CS{something_her3}
    # The hint says "something_her3" so let's try variations
    
    candidates = []
    
    # Try "something_her3" variations
    base = "something_her3"
    candidates.append(f"CS{{{base}}}")
    
    # Try with different separators
    for sep in ['_', '-', '']:
        parts = base.split('_')
        if len(parts) > 1:
            candidates.append(f"CS{{{sep.join(parts)}}}")
    
    # Try common CTF words
    words = ["flag", "reverse", "me", "r3", "m3", "r3m3", "challenge", "ctf", "her3", "here"]
    for w1 in words:
        for w2 in words:
            if w1 != w2:
                candidates.append(f"CS{{{w1}_{w2}}}")
                candidates.append(f"CS{{{w1}-{w2}}}")
    
    # Try the challenge name
    candidates.append("CS{R3_M3}")
    candidates.append("CS{r3_m3}")
    candidates.append("CS{R3M3}")
    candidates.append("CS{r3m3}")
    
    return candidates

def test_all_hashes():
    """Test all hash functions with candidates"""
    candidates = generate_flag_candidates()
    
    print("=== Testing all hash functions ===")
    print(f"Testing {len(candidates)} candidates...\n")
    
    for candidate in candidates:
        test_bytes = candidate.encode()
        length = len(test_bytes)
        
        # Test orbit_mist
        hash_mist = orbit_mist(test_bytes, length)
        if hash_mist in EXPECTED_HASHES:
            idx = EXPECTED_HASHES.index(hash_mist)
            print(f"✓ MATCH with orbit_mist!")
            print(f"  Flag: {candidate}")
            print(f"  Hash: 0x{hash_mist:016x}")
            print(f"  Matches expected[{idx}]\n")
            return candidate
        
        # Test orbit_ember
        hash_ember = orbit_ember(test_bytes, length)
        if hash_ember in EXPECTED_HASHES:
            idx = EXPECTED_HASHES.index(hash_ember)
            print(f"✓ MATCH with orbit_ember!")
            print(f"  Flag: {candidate}")
            print(f"  Hash: 0x{hash_ember:016x}")
            print(f"  Matches expected[{idx}]\n")
            return candidate
        
        # Test orbit_nova (final check)
        hash_nova = orbit_nova(test_bytes, length)
        if hash_nova == FINAL_CHECK:
            print(f"✓ MATCH with orbit_nova (FINAL CHECK)!")
            print(f"  Flag: {candidate}")
            print(f"  Hash: 0x{hash_nova:016x}\n")
            return candidate
    
    print("No matches found with generated candidates")
    return None

def try_brute_force_short():
    """Try brute forcing short flags"""
    print("\n=== Brute Force Short Flags ===")
    charset = string.ascii_lowercase + string.digits + '_'
    
    # Try 3-8 character flags inside CS{...}
    for length in range(3, 9):
        print(f"Trying length {length}...")
        count = 0
        for combo in itertools.product(charset, repeat=length):
            if count > 100000:  # Limit per length
                break
            test_str = f"CS{{{' '.join(combo)}}}"
            test_bytes = test_str.encode()
            
            # Quick test
            hash_val = orbit_mist(test_bytes, len(test_bytes))
            if hash_val in EXPECTED_HASHES:
                print(f"✓ FOUND: {test_str}")
                return test_str
            
            hash_val = orbit_ember(test_bytes, len(test_bytes))
            if hash_val in EXPECTED_HASHES:
                print(f"✓ FOUND: {test_str}")
                return test_str
            
            hash_val = orbit_nova(test_bytes, len(test_bytes))
            if hash_val == FINAL_CHECK:
                print(f"✓ FOUND (nova): {test_str}")
                return test_str
            
            count += 1
            if count % 10000 == 0:
                print(f"  Tested {count} combinations...")
    
    return None

if __name__ == '__main__':
    print("=== Comprehensive Solver ===")
    
    # Test with generated candidates
    result = test_all_hashes()
    if result:
        print(f"\n🎉 FLAG FOUND: {result}")
    else:
        # Try brute force
        result = try_brute_force_short()
        if result:
            print(f"\n🎉 FLAG FOUND: {result}")
        else:
            print("\n❌ Flag not found")


