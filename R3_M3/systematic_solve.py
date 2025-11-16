#!/usr/bin/env python3
"""
Systematic solver: Test all functions with all expected values
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

FUNCTIONS = [
    ('orbit_mist', orbit_mist),
    ('orbit_ember', orbit_ember),
    ('orbit_tide', orbit_tide),
    ('orbit_quartz', orbit_quartz),
    ('orbit_haze', orbit_haze),
    ('orbit_nova', orbit_nova),
]

def test_systematic():
    """Test systematically with all functions"""
    print("=== Systematic Testing ===")
    
    # Generate comprehensive test set
    test_candidates = []
    
    # Direct hint variations
    hints = ['something_her3', 'R3_M3_her3', 'r3_m3_her3', 'R3M3_her3', 
             'her3_something', 'her3_R3_M3', 'reverse_her3', 'flag_her3']
    
    for hint in hints:
        test_candidates.append(f"CS{{{hint}}}")
        test_candidates.append(f"CS{{{hint}_}}")
        test_candidates.append(f"CS{{_{hint}}}")
    
    # Challenge name variations
    for name in ['R3_M3', 'r3_m3', 'R3M3', 'r3m3']:
        for suffix in ['', '_her3', '_flag', '_challenge']:
            test_candidates.append(f"CS{{{name}{suffix}}}")
    
    # Common CTF patterns
    for word in ['flag', 'reverse', 'me', 'challenge', 'ctf']:
        test_candidates.append(f"CS{{{word}_her3}}")
        test_candidates.append(f"CS{{her3_{word}}}")
    
    print(f"Testing {len(test_candidates)} candidates with all functions...")
    
    for candidate in test_candidates:
        test_bytes = candidate.encode()
        length = len(test_bytes)
        
        for func_name, func in FUNCTIONS:
            try:
                hash_val = func(test_bytes, length)
                
                # Check all expected hashes
                for i, expected in enumerate(EXPECTED_HASHES):
                    if hash_val == expected:
                        print(f"\n✓✓✓ MATCH FOUND! ✓✓✓")
                        print(f"  Flag: {candidate}")
                        print(f"  Function: {func_name}")
                        print(f"  Hash: 0x{hash_val:016x}")
                        print(f"  Matches expected[{i}]")
                        return candidate
                
                # Check final
                if func_name == 'orbit_nova' and hash_val == FINAL_CHECK:
                    print(f"\n✓✓✓ MATCH FOUND (FINAL)! ✓✓✓")
                    print(f"  Flag: {candidate}")
                    print(f"  Function: {func_name}")
                    print(f"  Hash: 0x{hash_val:016x}")
                    return candidate
            except Exception as e:
                pass
    
    return None

def brute_force_focused():
    """Focused brute force on likely patterns"""
    print("\n=== Focused Brute Force ===")
    charset = string.ascii_lowercase + string.digits + '_'
    
    # Focus on patterns with "her3" and "r3", "m3"
    prefixes = ['r3', 'm3', 'r3m3', 'r3_m3']
    suffixes = ['her3', 'here', 'flag']
    middles = ['_', '-', '']
    
    # Generate focused candidates
    for prefix in prefixes:
        for middle in middles:
            for suffix in suffixes:
                test_str = f"CS{{{prefix}{middle}{suffix}}}"
                test_bytes = test_str.encode()
                
                for func_name, func in FUNCTIONS:
                    try:
                        hash_val = func(test_bytes, len(test_bytes))
                        for i, expected in enumerate(EXPECTED_HASHES):
                            if hash_val == expected:
                                print(f"\n✓✓✓ FOUND: {test_str}")
                                return test_str
                        if func_name == 'orbit_nova' and hash_val == FINAL_CHECK:
                            print(f"\n✓✓✓ FOUND: {test_str}")
                            return test_str
                    except:
                        pass
    
    # Try short brute force
    print("Trying short brute force (3-8 chars)...")
    for length in range(3, 9):
        count = 0
        for combo in itertools.product(charset, repeat=length):
            if count > 100000:
                break
            test_str = f"CS{{{' '.join(combo)}}}"
            test_bytes = test_str.encode()
            
            for func_name, func in FUNCTIONS:
                try:
                    hash_val = func(test_bytes, len(test_bytes))
                    if hash_val in EXPECTED_HASHES or (func_name == 'orbit_nova' and hash_val == FINAL_CHECK):
                        print(f"\n✓✓✓ FOUND: {test_str}")
                        return test_str
                except:
                    pass
            count += 1
    
    return None

if __name__ == '__main__':
    flag = test_systematic()
    if flag:
        print(f"\n🎉🎉🎉 FLAG: {flag} 🎉🎉🎉")
        exit(0)
    
    flag = brute_force_focused()
    if flag:
        print(f"\n🎉🎉🎉 FLAG: {flag} 🎉🎉🎉")
        exit(0)
    
    print("\nStill searching...")


