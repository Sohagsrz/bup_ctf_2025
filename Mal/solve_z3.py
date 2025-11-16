#!/usr/bin/env python3
"""
Use Z3 constraint solver to reverse the hash.
"""

try:
    from z3 import *
    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False
    print("Z3 not available. Install with: pip3 install z3-solver")

def hash_string(s):
    """Hash function matching the binary"""
    hash_val = 0x1505
    for c in s:
        hash_val = ((hash_val << 5) + hash_val + ord(c)) & 0xFFFFFFFF
    return hash_val

if Z3_AVAILABLE:
    def solve_with_z3(target_hash, max_length=40):
        """Use Z3 to solve for the flag"""
        print(f"Using Z3 to solve hash 0x{target_hash:x}...")
        
        s = Solver()
        
        # Create character variables
        chars = [BitVec(f'c{i}', 8) for i in range(max_length)]
        
        # Constraints: printable ASCII (32-126)
        for c in chars:
            s.add(c >= 32)
            s.add(c < 127)
        
        # Hash calculation
        hash_val = BitVecVal(0x1505, 32)
        for c in chars:
            hash_val = hash_val * BitVecVal(33, 32) + ZeroExt(24, c)
            hash_val = hash_val & BitVecVal(0xFFFFFFFF, 32)
        
        # Target hash
        s.add(hash_val == BitVecVal(target_hash, 32))
        
        # Try to find a solution
        print("Solving...")
        if s.check() == sat:
            model = s.model()
            result_chars = []
            for c in chars:
                val = model[c].as_long()
                if val >= 32 and val < 127:
                    result_chars.append(chr(val))
                else:
                    break
            result = ''.join(result_chars)
            # Remove trailing nulls/whitespace
            result = result.rstrip('\x00').rstrip()
            return result
        return None
    
    # Try different lengths
    for length in range(10, 50, 5):
        print(f"\nTrying length {length}...")
        result = solve_with_z3(0x72d59e59, length)
        if result:
            print(f"\n[+] Found: {result}")
            print(f"[+] Verification: hash = 0x{hash_string(result):08x}")
            if hash_string(result) == 0x72d59e59:
                print("[+] CORRECT!")
                break
        else:
            print(f"  No solution for length {length}")
else:
    print("Z3 not available. Please install z3-solver:")
    print("  pip3 install z3-solver")

