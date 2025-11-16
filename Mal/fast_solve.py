#!/usr/bin/env python3
"""
Fast solution finder - try different strategies quickly
"""

def hash_string(s):
    hash_val = 0x1505
    for c in s:
        hash_val = ((hash_val << 5) + hash_val + ord(c)) & 0xFFFFFFFF
    return hash_val

import sys
sys.path.insert(0, 'venv/lib/python3.13/site-packages')

target = 0x72d59e59

print("Fast solution finder...")
print(f"Target hash: 0x{target:08x}")
print()

# Strategy 1: Try Z3 with specific length constraints
try:
    from z3 import *
    
    print("Strategy 1: Z3 with CS{...} format constraint")
    print("-" * 70)
    
    for length in range(10, 16):
        s = Solver()
        chars = [BitVec(f'c{i}', 8) for i in range(length)]
        
        # Force CS{...} format
        if length >= 4:
            s.add(chars[0] == ord('C'))
            s.add(chars[1] == ord('S'))
            s.add(chars[2] == ord('{'))
            s.add(chars[length-1] == ord('}'))
        
        # Inner chars: printable
        for i in range(3, length-1):
            s.add(chars[i] >= 32, chars[i] < 127)
        
        # Hash
        hash_val = BitVecVal(0x1505, 32)
        for c in chars:
            hash_val = hash_val * BitVecVal(33, 32) + ZeroExt(24, c)
        s.add(hash_val == BitVecVal(target, 32))
        
        if s.check() == sat:
            model = s.model()
            result = ''.join([chr(model[c].as_long()) for c in chars])
            h = hash_string(result)
            if h == target:
                print(f"✓ Found: {result}")
                print(f"  Hash: 0x{h:08x}")
                print()
                print("=" * 70)
                print(f"FLAG: {result}")
                print("=" * 70)
                exit(0)
    
    print("No solution with CS{...} format found")
    print()
    
    # Strategy 2: Try without format constraint
    print("Strategy 2: Z3 without format constraint")
    print("-" * 70)
    
    for length in [10, 11, 12, 13, 14]:
        s = Solver()
        chars = [BitVec(f'c{i}', 8) for i in range(length)]
        
        for c in chars:
            s.add(c >= 32, c < 127)
        
        hash_val = BitVecVal(0x1505, 32)
        for c in chars:
            hash_val = hash_val * BitVecVal(33, 32) + ZeroExt(24, c)
        s.add(hash_val == BitVecVal(target, 32))
        
        if s.check() == sat:
            model = s.model()
            result = ''.join([chr(model[c].as_long()) for c in chars]).rstrip('\x00')
            h = hash_string(result)
            if h == target:
                print(f"✓ Found: {result}")
                # Check if it can be formatted as CS{...}
                if not result.startswith('CS{'):
                    print(f"  Note: This doesn't have CS{{...}} format")
                    print(f"  Try: CS{{{result}}}")
                    test = f"CS{{{result}}}"
                    h_test = hash_string(test)
                    if h_test == target:
                        print(f"  ✓ CS{{{result}}} also works!")
                        print()
                        print("=" * 70)
                        print(f"FLAG: CS{{{result}}}")
                        print("=" * 70)
                        exit(0)
                    else:
                        print(f"  ✗ CS{{{result}}} doesn't work (hash: 0x{h_test:08x})")
                else:
                    print()
                    print("=" * 70)
                    print(f"FLAG: {result}")
                    print("=" * 70)
                    exit(0)
                break

except ImportError:
    print("Z3 not available")
except Exception as e:
    print(f"Error: {e}")

print("\n[-] Could not find solution")


