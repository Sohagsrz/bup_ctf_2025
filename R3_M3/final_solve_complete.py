#!/usr/bin/env python3
"""
Final complete solver - test all hash functions with all expected values
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

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

def test_all():
    """Test all possible flag formats"""
    print("=== Final Complete Flag Search ===")
    
    # Generate comprehensive test set
    candidates = []
    
    # Direct patterns
    patterns = [
        'something_her3', 'R3_M3_her3', 'r3_m3_her3', 'R3M3_her3',
        'her3_something', 'her3_R3_M3', 'reverse_her3', 'flag_her3',
        'R3_M3', 'her3', 'R3M3', 'r3m3',
        'R3_M3_flag', 'flag_R3_M3', 'challenge_her3', 'ctf_her3',
    ]
    
    for pattern in patterns:
        candidates.append(f"CS{{{pattern}}}")
        candidates.append(f"CS{{{pattern}_}}")
        candidates.append(f"CS{{_{pattern}}}")
    
    # Try all combinations of key words
    words = ['R3', 'M3', 'r3', 'm3', 'her3', 'something', 'reverse', 'flag']
    seps = ['_', '-', '']
    
    for w1 in words[:4]:  # Limit to avoid too many
        for sep1 in seps:
            for w2 in words[:4]:
                if w1 == w2:
                    continue
                candidates.append(f"CS{{{w1}{sep1}{w2}}}")
    
    print(f"Testing {len(candidates)} candidates...")
    
    for candidate in candidates:
        test_bytes = candidate.encode()
        length = len(test_bytes)
        
        for func_name, func in FUNCTIONS:
            try:
                hash_val = func(test_bytes, length)
                
                # Check all expected
                for i, expected in enumerate(EXPECTED_HASHES):
                    if hash_val == expected:
                        print(f"\n{'='*70}")
                        print(f"🎉🎉🎉 FLAG FOUND! 🎉🎉🎉")
                        print(f"{'='*70}")
                        print(f"Flag: {candidate}")
                        print(f"Function: {func_name}")
                        print(f"Hash: 0x{hash_val:016x}")
                        print(f"Matches: expected[{i}] = 0x{expected:016x}")
                        print(f"{'='*70}")
                        return candidate
                
                # Check final
                if func_name == 'orbit_nova' and hash_val == FINAL_CHECK:
                    print(f"\n{'='*70}")
                    print(f"🎉🎉🎉 FLAG FOUND (FINAL CHECK)! 🎉🎉🎉")
                    print(f"{'='*70}")
                    print(f"Flag: {candidate}")
                    print(f"Function: {func_name}")
                    print(f"Hash: 0x{hash_val:016x}")
                    print(f"Matches: FINAL_CHECK = 0x{FINAL_CHECK:016x}")
                    print(f"{'='*70}")
                    return candidate
            except Exception as e:
                pass
    
    # Try brute force on shorter flags
    print("\n=== Brute Force Short Flags ===")
    charset = string.ascii_lowercase + string.digits + '_'
    
    for length in range(3, 12):
        print(f"Length {length}...")
        count = 0
        for combo in itertools.product(charset, repeat=length):
            if count > 50000:
                break
            
            test_str = f"CS{{{' '.join(combo)}}}"
            test_bytes = test_str.encode()
            
            for func_name, func in FUNCTIONS:
                try:
                    hash_val = func(test_bytes, len(test_bytes))
                    if hash_val in EXPECTED_HASHES:
                        print(f"\n🎉 FOUND: {test_str}")
                        return test_str
                    if func_name == 'orbit_nova' and hash_val == FINAL_CHECK:
                        print(f"\n🎉 FOUND: {test_str}")
                        return test_str
                except:
                    pass
            
            count += 1
            if count % 10000 == 0:
                print(f"  Tested {count}...")
    
    return None

if __name__ == '__main__':
    flag = test_all()
    if flag:
        print(f"\n✅✅✅ FINAL FLAG: {flag} ✅✅✅")
        with open('FLAG.txt', 'w') as f:
            f.write(flag)
        print("Flag saved to FLAG.txt")
    else:
        print("\n❌ Flag not found")


