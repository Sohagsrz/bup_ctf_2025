#!/usr/bin/env python3
"""
Find alternative flag solutions - maybe there's a different one that's correct
"""

def hash_string(s):
    hash_val = 0x1505
    for c in s:
        hash_val = ((hash_val << 5) + hash_val + ord(c)) & 0xFFFFFFFF
    return hash_val

try:
    import sys
    sys.path.insert(0, 'venv/lib/python3.13/site-packages')
    from z3 import *
    
    target = 0x72d59e59
    
    print("Finding alternative solutions with Z3...")
    print(f"Target: 0x{target:08x}")
    print()
    
    solutions = []
    
    # Try different lengths and find multiple solutions
    for length in range(10, 18):
        print(f"Length {length}:")
        s = Solver()
        chars = [BitVec(f'c{i}', 8) for i in range(length)]
        
        for c in chars:
            s.add(c >= 32, c < 127)
        
        hash_val = BitVecVal(0x1505, 32)
        for c in chars:
            hash_val = hash_val * BitVecVal(33, 32) + ZeroExt(24, c)
        
        s.add(hash_val == BitVecVal(target, 32))
        
        # Find first 3 solutions for this length
        for sol_num in range(3):
            if s.check() == sat:
                model = s.model()
                result = ''.join([chr(model[c].as_long()) for c in chars]).rstrip('\x00')
                
                if result and result not in solutions:
                    solutions.append(result)
                    h = hash_string(result)
                    is_cs = "CS{...}" if result.startswith('CS{') and result.endswith('}') else ""
                    print(f"  Solution {len(solutions)}: {result} {is_cs}")
                    
                    # Add constraint to find different solution
                    s.add(Or([chars[i] != BitVecVal(ord(result[i]), 8) 
                             for i in range(min(len(result), length))]))
            else:
                break
    
    print(f"\n{'='*70}")
    print(f"Found {len(solutions)} total solutions")
    print("="*70)
    
    # Show CS{...} format solutions
    cs_solutions = [s for s in solutions if s.startswith('CS{') and s.endswith('}')]
    if cs_solutions:
        print("\nCS{...} format solutions:")
        for sol in cs_solutions:
            print(f"  {sol}")
            h = hash_string(sol)
            print(f"    Hash: 0x{h:08x} {'✓' if h == target else '✗'}")
    
    if not cs_solutions:
        print("\nNo CS{...} format solutions found in this batch")
        print("First few solutions found:")
        for i, sol in enumerate(solutions[:5], 1):
            print(f"  {i}. {sol}")

except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()


