#!/usr/bin/env python3
"""
Find ALL possible solutions that hash to the target value.
Maybe the flag is a different one.
"""

def hash_string(s):
    """Hash function matching the binary"""
    hash_val = 0x1505
    for c in s:
        hash_val = ((hash_val << 5) + hash_val + ord(c)) & 0xFFFFFFFF
    return hash_val

try:
    from z3 import *
    
    def find_all_solutions(target_hash, max_length=20, max_solutions=100):
        """Find multiple solutions using Z3"""
        solutions = []
        
        for length in range(5, max_length + 1):
            print(f"\nTrying length {length}...")
            s = Solver()
            
            # Create character variables
            chars = [BitVec(f'c{i}', 8) for i in range(length)]
            
            # Constraints: printable ASCII (32-126)
            for c in chars:
                s.add(c >= 32)
                s.add(c < 127)
            
            # Hash calculation
            hash_val = BitVecVal(0x1505, 32)
            for c in chars:
                hash_val = hash_val * BitVecVal(33, 32) + ZeroExt(24, c)
            
            # Target hash
            s.add(hash_val == BitVecVal(target_hash, 32))
            
            # Find multiple solutions
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
                result = ''.join(result_chars)
                result = result.rstrip('\x00').rstrip()
                
                if result and result not in solutions:
                    solutions.append(result)
                    print(f"  Solution {len(solutions)}: {result}")
                    
                    # Add constraint to find different solution
                    s.add(Or([chars[i] != BitVecVal(ord(result[i]), 8) for i in range(min(len(result), length))]))
                
                count += 1
                if count >= 10:  # Limit per length
                    break
        
        return solutions
    
    target = 0x72d59e59
    print("Finding ALL solutions that hash to 0x72d59e59...")
    print("=" * 70)
    
    solutions = find_all_solutions(target, max_length=25, max_solutions=50)
    
    print("\n" + "=" * 70)
    print(f"Found {len(solutions)} unique solutions:")
    print("=" * 70)
    
    # Filter for CS{...} format
    cs_format = [s for s in solutions if s.startswith('CS{') and s.endswith('}')]
    if cs_format:
        print("\nSolutions with CS{...} format:")
        for sol in cs_format:
            print(f"  {sol}")
    
    # Show all solutions
    print("\nAll solutions:")
    for i, sol in enumerate(solutions[:20], 1):
        print(f"  {i}. {sol}")
        # Verify
        h = hash_string(sol)
        if h == target:
            print(f"      ✓ Hash matches: 0x{h:08x}")
        else:
            print(f"      ✗ Hash mismatch: 0x{h:08x}")
    
    if len(solutions) > 20:
        print(f"  ... and {len(solutions) - 20} more")
    
except ImportError:
    print("Z3 not available")


