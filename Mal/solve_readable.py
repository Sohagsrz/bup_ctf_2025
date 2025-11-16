#!/usr/bin/env python3
"""
Find more readable/meaningful solutions using Z3 with additional constraints
"""

def hash_string(s):
    hash_val = 0x1505
    for c in s:
        hash_val = ((hash_val << 5) + hash_val + ord(c)) & 0xFFFFFFFF
    return hash_val

try:
    from z3 import *
    
    target = 0x72d59e59
    
    def find_readable_solution(length):
        """Find solution with preference for alphanumeric characters"""
        s = Solver()
        
        chars = [BitVec(f'c{i}', 8) for i in range(length)]
        
        # Prefer alphanumeric and common flag characters
        for i, c in enumerate(chars):
            # Allow printable ASCII but prefer alphanumeric
            s.add(c >= 32)
            s.add(c < 127)
            
            # If it's in CS{...} format, constrain accordingly
            if i < 3:
                # First 3 chars should be "CS{"
                s.add(c == ord("CS{"[i]))
            elif i == length - 1:
                # Last char should be "}"
                s.add(c == ord("}"))
            else:
                # Inner chars: prefer alphanumeric, underscore, dash
                # But allow any printable
                pass
        
        # Hash calculation
        hash_val = BitVecVal(0x1505, 32)
        for c in chars:
            hash_val = hash_val * BitVecVal(33, 32) + ZeroExt(24, c)
        
        s.add(hash_val == BitVecVal(target, 32))
        
        if s.check() == sat:
            model = s.model()
            result = ''.join([chr(model[c].as_long()) for c in chars])
            return result
        return None
    
    print("Finding readable solutions...")
    print(f"Target: 0x{target:08x}")
    print()
    
    # Try different lengths
    for length in range(8, 25):
        print(f"Trying length {length}...")
        result = find_readable_solution(length)
        if result:
            print(f"\n[+] Found: {result}")
            h = hash_string(result)
            print(f"[+] Hash: 0x{h:08x}")
            if h == target:
                print("[+] CORRECT!")
                print(f"\n{'='*70}")
                print(f"FLAG: {result}")
                print(f"{'='*70}")
                break
        else:
            print(f"  No solution for length {length}")

except ImportError:
    print("Z3 not available")


