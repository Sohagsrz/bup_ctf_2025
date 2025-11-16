#!/usr/bin/env python3
"""
Test all possible function-to-expected-hash mappings
"""

from all_hashes import orbit_mist, orbit_ember, orbit_tide, orbit_quartz, orbit_haze, orbit_nova
import string
import itertools

EXPECTED_HASHES = [
    0x49ec606db1d2e62d,
    0x2ab1ab1ec269421e,
    0xe49a159a174cbcf8,
    0x47f34a499b2edd93,
    0x237a429b80010643
]

FINAL_CHECK = 0xFCE62D194453D523

# Based on analysis: lanes likely maps to function indices
# lanes[0] = 1 -> orbit_ember (index 1)
# lanes[1] = 0x200000001 -> might be (2,1) -> (tide, ember) or just index 2
# lanes[2] = 0 -> orbit_mist (index 0)
# lanes[3] = 0 -> orbit_mist (index 0)
# lanes[4] = 0x3050 -> unknown

FUNCTIONS = [
    (0, 'orbit_mist', orbit_mist),
    (1, 'orbit_ember', orbit_ember),
    (2, 'orbit_tide', orbit_tide),
    (3, 'orbit_quartz', orbit_quartz),
    (4, 'orbit_haze', orbit_haze),
]

# Try different interpretations of lanes[1]
# Option 1: lanes[1] = 2 (orbit_tide)
# Option 2: lanes[1] = 1 (orbit_ember) 
# Option 3: lanes[1] uses both high and low 32 bits

# Let's test: expected[0] with orbit_ember, expected[1] with orbit_tide, etc.
MAPPINGS = [
    # Mapping: (expected_idx, function_idx, function_name, function)
    (0, 1, 'orbit_ember', orbit_ember),  # lanes[0] = 1
    (1, 2, 'orbit_tide', orbit_tide),   # lanes[1] = 2 (from high 32 bits)
    (2, 0, 'orbit_mist', orbit_mist),   # lanes[2] = 0
    (3, 0, 'orbit_mist', orbit_mist),   # lanes[3] = 0
    (4, 3, 'orbit_quartz', orbit_quartz), # lanes[4] might be 3
]

def test_with_mapping():
    """Test inputs with the assumed mapping"""
    print("=== Testing with Function Mapping ===")
    print("Mapping:")
    for exp_idx, func_idx, func_name, _ in MAPPINGS:
        print(f"  expected[{exp_idx}] -> {func_name}")
    
    # Generate test candidates
    candidates = []
    
    # Based on hint "something_her3" and challenge name "R3 M3"
    base_patterns = [
        'something_her3',
        'R3_M3_her3',
        'r3_m3_her3', 
        'R3M3_her3',
        'her3_something',
        'her3_R3_M3',
        'reverse_her3',
        'flag_her3',
    ]
    
    for pattern in base_patterns:
        candidates.append(f"CS{{{pattern}}}")
        candidates.append(f"CS{{{pattern}_}}")
        candidates.append(f"CS{{_{pattern}}}")
    
    # Also try variations
    for sep in ['_', '-', '']:
        candidates.append(f"CS{{R3{sep}M3{sep}her3}}")
        candidates.append(f"CS{{something{sep}her3}}")
    
    print(f"\nTesting {len(candidates)} candidates...")
    
    for candidate in candidates:
        test_bytes = candidate.encode()
        length = len(test_bytes)
        
        # Test each mapping
        for exp_idx, func_idx, func_name, func in MAPPINGS:
            try:
                hash_val = func(test_bytes, length)
                if hash_val == EXPECTED_HASHES[exp_idx]:
                    print(f"\n✓ MATCH FOUND!")
                    print(f"  Flag: {candidate}")
                    print(f"  Function: {func_name}")
                    print(f"  Hash: 0x{hash_val:016x}")
                    print(f"  Matches expected[{exp_idx}]")
                    return candidate
            except Exception as e:
                pass
        
        # Also test orbit_nova for final check
        try:
            hash_val = orbit_nova(test_bytes, length)
            if hash_val == FINAL_CHECK:
                print(f"\n✓ MATCH FOUND (FINAL CHECK)!")
                print(f"  Flag: {candidate}")
                print(f"  Function: orbit_nova")
                print(f"  Hash: 0x{hash_val:016x}")
                return candidate
        except:
            pass
    
    return None

def brute_force_with_mapping():
    """Brute force with the mapping"""
    print("\n=== Brute Force with Mapping ===")
    charset = string.ascii_lowercase + string.digits + '_'
    
    # Try shorter lengths first
    for length in range(3, 10):
        print(f"Trying length {length}...")
        count = 0
        max_tests = 200000
        
        for combo in itertools.product(charset, repeat=length):
            if count >= max_tests:
                break
            
            test_str = f"CS{{{' '.join(combo)}}}"
            test_bytes = test_str.encode()
            
            # Test with mapping
            for exp_idx, func_idx, func_name, func in MAPPINGS:
                try:
                    hash_val = func(test_bytes, len(test_bytes))
                    if hash_val == EXPECTED_HASHES[exp_idx]:
                        print(f"\n✓ FOUND: {test_str}")
                        print(f"  Function: {func_name}, Expected: {exp_idx}")
                        return test_str
                except:
                    pass
            
            # Test orbit_nova
            try:
                hash_val = orbit_nova(test_bytes, len(test_bytes))
                if hash_val == FINAL_CHECK:
                    print(f"\n✓ FOUND: {test_str}")
                    print(f"  Function: orbit_nova (FINAL)")
                    return test_str
            except:
                pass
            
            count += 1
            if count % 50000 == 0:
                print(f"  Tested {count}...")
    
    return None

if __name__ == '__main__':
    print("=== Testing All Mappings ===")
    
    # Test with mapping
    flag = test_with_mapping()
    if flag:
        print(f"\n🎉 FLAG: {flag}")
        exit(0)
    
    # Try brute force
    flag = brute_force_with_mapping()
    if flag:
        print(f"\n🎉 FLAG: {flag}")
        exit(0)
    
    print("\n❌ Not found")


