#!/usr/bin/env python3
"""
Complete solver - test all possibilities systematically
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from all_hashes import orbit_mist, orbit_ember, orbit_tide, orbit_quartz, orbit_haze, orbit_nova

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

def comprehensive_test():
    """Comprehensive test of all possibilities"""
    print("=== Comprehensive Flag Search ===")
    
    # Generate all possible flag candidates
    candidates = set()
    
    # Based on hint "something_her3" and challenge "R3 M3"
    base_words = ['something', 'R3', 'M3', 'r3', 'm3', 'R3M3', 'r3m3', 'R3_M3', 'r3_m3', 
                   'her3', 'here', 'reverse', 'flag', 'challenge', 'ctf']
    separators = ['_', '-', '']
    
    # Generate combinations
    for w1 in base_words:
        for sep in separators:
            for w2 in base_words:
                if w1 != w2:
                    candidates.add(f"CS{{{w1}{sep}{w2}}}")
                    candidates.add(f"CS{{{w2}{sep}{w1}}}")
    
    # Specific patterns
    candidates.update([
        'CS{something_her3}',
        'CS{R3_M3_her3}',
        'CS{r3_m3_her3}',
        'CS{R3M3_her3}',
        'CS{her3_something}',
        'CS{her3_R3_M3}',
        'CS{reverse_her3}',
        'CS{flag_her3}',
        'CS{R3_M3}',
        'CS{her3}',
        'CS{R3M3}',
        'CS{r3m3}',
    ])
    
    print(f"Testing {len(candidates)} candidates...")
    
    for candidate in sorted(candidates):
        test_bytes = candidate.encode()
        length = len(test_bytes)
        
        for func_name, func in FUNCTIONS:
            try:
                hash_val = func(test_bytes, length)
                
                # Check all expected
                for i, expected in enumerate(EXPECTED_HASHES):
                    if hash_val == expected:
                        print(f"\n{'='*60}")
                        print(f"🎉 FLAG FOUND! 🎉")
                        print(f"{'='*60}")
                        print(f"Flag: {candidate}")
                        print(f"Function: {func_name}")
                        print(f"Hash: 0x{hash_val:016x}")
                        print(f"Matches: expected[{i}]")
                        print(f"{'='*60}")
                        return candidate
                
                # Check final
                if func_name == 'orbit_nova' and hash_val == FINAL_CHECK:
                    print(f"\n{'='*60}")
                    print(f"🎉 FLAG FOUND (FINAL CHECK)! 🎉")
                    print(f"{'='*60}")
                    print(f"Flag: {candidate}")
                    print(f"Function: {func_name}")
                    print(f"Hash: 0x{hash_val:016x}")
                    print(f"{'='*60}")
                    return candidate
            except Exception as e:
                pass
    
    return None

if __name__ == '__main__':
    flag = comprehensive_test()
    if flag:
        print(f"\n✅ FINAL FLAG: {flag}")
        # Write to file
        with open('FLAG.txt', 'w') as f:
            f.write(flag)
        print(f"Flag saved to FLAG.txt")
    else:
        print("\nFlag not found in candidates")
        print("Trying extended search...")


