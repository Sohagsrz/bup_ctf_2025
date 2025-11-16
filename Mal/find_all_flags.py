#!/usr/bin/env python3
"""
Comprehensive solution finder - find ALL solutions that hash correctly
"""

def hash_string(s):
    hash_val = 0x1505
    for c in s:
        hash_val = ((hash_val << 5) + hash_val + ord(c)) & 0xFFFFFFFF
    return hash_val

import sys
sys.path.insert(0, 'venv/lib/python3.13/site-packages')

try:
    from z3 import *
    
    target = 0x72d59e59
    all_solutions = []
    
    print("=" * 70)
    print("Finding ALL solutions that hash to 0x72d59e59")
    print("=" * 70)
    print()
    
    # Try different lengths and find multiple solutions for each
    for length in range(8, 25):
        print(f"Length {length}:")
        solutions_this_length = []
        s = Solver()
        
        chars = [BitVec(f'c{i}', 8) for i in range(length)]
        
        # Printable ASCII
        for c in chars:
            s.add(c >= 32, c < 127)
        
        # Hash calculation
        hash_val = BitVecVal(0x1505, 32)
        for c in chars:
            hash_val = hash_val * BitVecVal(33, 32) + ZeroExt(24, c)
        
        s.add(hash_val == BitVecVal(target, 32))
        
        # Find up to 10 solutions for this length
        solution_count = 0
        while s.check() == sat and solution_count < 10:
            model = s.model()
            result_chars = []
            for c in chars:
                val = model[c].as_long()
                if val >= 32 and val < 127:
                    result_chars.append(chr(val))
                else:
                    break
            
            result = ''.join(result_chars).rstrip('\x00').rstrip()
            
            if result and result not in all_solutions:
                all_solutions.append(result)
                solutions_this_length.append(result)
                
                # Verify hash
                h = hash_string(result)
                is_cs = "✓ CS{...}" if result.startswith('CS{') and result.endswith('}') else ""
                match = "✓" if h == target else "✗"
                print(f"  {len(all_solutions)}. {result:20} {match} {is_cs}")
                
                # Add constraint to find different solution
                constraints = []
                for i in range(min(len(result), length)):
                    constraints.append(chars[i] != BitVecVal(ord(result[i]), 8))
                if constraints:
                    s.add(Or(constraints))
            
            solution_count += 1
        
        if solutions_this_length:
            print(f"  Found {len(solutions_this_length)} solutions for length {length}")
        else:
            print(f"  No solutions for length {length}")
        print()
    
    print("=" * 70)
    print(f"Total solutions found: {len(all_solutions)}")
    print("=" * 70)
    
    # Filter CS{...} format
    cs_solutions = [s for s in all_solutions if s.startswith('CS{') and s.endswith('}')]
    
    if cs_solutions:
        print(f"\n✓ Found {len(cs_solutions)} solutions with CS{{...}} format:")
        print("-" * 70)
        for i, sol in enumerate(cs_solutions, 1):
            h = hash_string(sol)
            print(f"{i}. {sol}")
            print(f"   Hash: 0x{h:08x} {'✓ CORRECT' if h == target else '✗ WRONG'}")
            print()
        
        # The first CS{...} solution is likely the flag
        if cs_solutions:
            flag = cs_solutions[0]
            print("=" * 70)
            print(f"FLAG: {flag}")
            print("=" * 70)
    else:
        print("\nNo CS{...} format solutions found")
        print("All solutions found:")
        for i, sol in enumerate(all_solutions[:20], 1):
            print(f"{i}. {sol}")

except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()


