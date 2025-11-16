#!/usr/bin/env python3
"""Find a flag with actual words"""
from z3 import *

def hash_string(s):
    h = 0x1505
    for c in s:
        h = ((h << 5) + h + ord(c)) & 0xFFFFFFFF
    return h

target = 0x72d59e59

# Try longer lengths with word-like constraints
for length in range(25, 45):
    print(f"Trying length {length}...")
    s = Solver()
    chars = [BitVec(f'c{i}', 8) for i in range(length)]
    
    # CS{...} format
    s.add(chars[0] == ord('C'))
    s.add(chars[1] == ord('S'))
    s.add(chars[2] == ord('{'))
    s.add(chars[length-1] == ord('}'))
    
    # Middle chars: allow letters, numbers, spaces, underscore, dash
    for i in range(3, length-1):
        s.add(Or(
            And(chars[i] >= ord('a'), chars[i] <= ord('z')),
            And(chars[i] >= ord('A'), chars[i] <= ord('Z')),
            And(chars[i] >= ord('0'), chars[i] <= ord('9')),
            chars[i] == ord(' '),
            chars[i] == ord('_'),
            chars[i] == ord('-')
        ))
    
    # Hash calculation
    h = BitVecVal(0x1505, 32)
    for c in chars:
        h = h * BitVecVal(33, 32) + ZeroExt(24, c)
        h = h & BitVecVal(0xFFFFFFFF, 32)
    s.add(h == BitVecVal(target, 32))
    
    # Try to find multiple solutions
    solutions = []
    while s.check() == sat and len(solutions) < 10:
        model = s.model()
        result = ''.join(chr(model[c].as_long()) for c in chars)
        result = result.rstrip('\x00').rstrip()
        
        # Check if it has spaces (words)
        if ' ' in result or result.count('_') >= 2:
            print(f"\n[+] FOUND: {result}")
            print(f"[+] Verification: 0x{hash_string(result):08x}")
            if hash_string(result) == target:
                print("[+] ✓ CORRECT!")
                solutions.append(result)
        
        # Add constraint for next solution
        s.add(Or([chars[i] != model[chars[i]] for i in range(length)]))
    
    if solutions:
        print(f"\nFound {len(solutions)} solutions with words:")
        for sol in solutions:
            print(f"  {sol}")
        break


