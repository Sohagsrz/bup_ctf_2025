#!/usr/bin/env python3
"""
Solve for flag with CS{...} format
"""

def hash_string(s):
    """Hash function matching the binary"""
    hash_val = 0x1505
    for c in s:
        hash_val = ((hash_val << 5) + hash_val + ord(c)) & 0xFFFFFFFF
    return hash_val

try:
    from z3 import *
    
    def solve_with_prefix_suffix(target_hash, prefix="CS{", suffix="}", max_inner_length=50):
        """Solve for flag with specific prefix and suffix"""
        print(f"Solving with prefix '{prefix}' and suffix '{suffix}'...")
        
        s = Solver()
        
        # Create character variables for the inner part
        chars = [BitVec(f'c{i}', 8) for i in range(max_inner_length)]
        
        # Constraints: printable ASCII (32-126)
        for c in chars:
            s.add(c >= 32)
            s.add(c < 127)
        
        # Hash calculation starting from prefix
        hash_val = BitVecVal(0x1505, 32)
        
        # Add prefix
        for c in prefix:
            hash_val = hash_val * BitVecVal(33, 32) + BitVecVal(ord(c), 32)
        
        # Add inner characters
        for c in chars:
            hash_val = hash_val * BitVecVal(33, 32) + ZeroExt(24, c)
        
        # Add suffix
        for c in suffix:
            hash_val = hash_val * BitVecVal(33, 32) + BitVecVal(ord(c), 32)
        
        # Target hash
        s.add(hash_val == BitVecVal(target_hash, 32))
        
        print("Solving with Z3...")
        if s.check() == sat:
            model = s.model()
            result_chars = []
            for c in chars:
                val = model[c].as_long()
                if val >= 32 and val < 127:
                    result_chars.append(chr(val))
                else:
                    break
            inner = ''.join(result_chars)
            result = prefix + inner + suffix
            return result
        return None
    
    target = 0x72d59e59
    
    # Try different inner lengths
    for length in range(5, 30, 1):
        print(f"\nTrying inner length {length}...")
        result = solve_with_prefix_suffix(target, max_inner_length=length)
        if result:
            print(f"\n[+] Found: {result}")
            print(f"[+] Verification: hash = 0x{hash_string(result):08x}")
            if hash_string(result) == target:
                print("[+] CORRECT!")
                print(f"\n{'='*70}")
                print(f"FLAG: {result}")
                print(f"{'='*70}")
                break
        else:
            print(f"  No solution for length {length}")
    
    # Also check if the found string without CS{} is the actual flag
    # (sometimes the flag format is just for submission)
    found_string = "j!y=9Dgt7D"
    print(f"\n{'='*70}")
    print("Alternative: The flag might be the inner part only")
    print(f"Found string: {found_string}")
    print(f"Hash verification: 0x{hash_string(found_string):08x} == 0x{target:08x}")
    print(f"Submission format: CS{{{found_string}}}")
    print(f"{'='*70}")
    
except ImportError:
    print("Z3 not available")


