#!/usr/bin/env python3
"""
Use Z3 to find multiple solutions, maybe the flag is different
"""

def hash_string(s):
    hash_val = 0x1505
    for c in s:
        hash_val = ((hash_val << 5) + hash_val + ord(c)) & 0xFFFFFFFF
    return hash_val

try:
    from z3 import *
    
    target = 0x72d59e59
    
    def find_solutions_with_length(length, max_solutions=10):
        """Find solutions of a specific length"""
        solutions = []
        s = Solver()
        
        chars = [BitVec(f'c{i}', 8) for i in range(length)]
        
        # Printable ASCII
        for c in chars:
            s.add(c >= 32)
            s.add(c < 127)
        
        # Hash calculation
        hash_val = BitVecVal(0x1505, 32)
        for c in chars:
            hash_val = hash_val * BitVecVal(33, 32) + ZeroExt(24, c)
        
        s.add(hash_val == BitVecVal(target, 32))
        
        count = 0
        while s.check() == sat and count < max_solutions:
            model = s.model()
            result_chars = []
            for c in chars:
                val = model[c].as_long()
                if val >= 32 and val < 127:
                    result_chars.append(chr(val))
                else:
                    break
            result = ''.join(result_chars).rstrip('\x00').rstrip()
            
            if result and result not in solutions:
                solutions.append(result)
                print(f"  Solution {len(solutions)}: {result}")
                
                # Add constraint for next solution
                s.add(Or([chars[i] != BitVecVal(ord(result[i]), 8) 
                         for i in range(min(len(result), length))]))
            
            count += 1
        
        return solutions
    
    print("Finding multiple solutions with Z3...")
    print(f"Target hash: 0x{target:08x}")
    print()
    
    all_solutions = []
    
    # Try different lengths
    for length in range(8, 20):
        print(f"\nLength {length}:")
        sols = find_solutions_with_length(length, max_solutions=5)
        all_solutions.extend(sols)
        
        # Check for CS{...} format
        cs_sols = [s for s in sols if s.startswith('CS{') and s.endswith('}')]
        if cs_sols:
            print(f"  Found CS{{...}} format: {cs_sols}")
    
    print("\n" + "="*70)
    print(f"Total solutions found: {len(all_solutions)}")
    print("="*70)
    
    # Show all CS{...} format solutions
    cs_format = [s for s in all_solutions if s.startswith('CS{') and s.endswith('}')]
    if cs_format:
        print("\nCS{...} format solutions:")
        for sol in cs_format:
            print(f"  {sol}")
            h = hash_string(sol)
            print(f"    Hash: 0x{h:08x} {'✓' if h == target else '✗'}")
    
    # Show first 10 solutions
    print("\nFirst 10 solutions:")
    for i, sol in enumerate(all_solutions[:10], 1):
        print(f"  {i}. {sol}")
        h = hash_string(sol)
        print(f"      Hash: 0x{h:08x} {'✓' if h == target else '✗'}")

except ImportError:
    print("Z3 not available")


