#!/usr/bin/env python3
"""
Use Z3 to find a longer, human-readable flag
"""

def hash_string(s):
    hash_val = 0x1505
    for c in s:
        hash_val = ((hash_val << 5) + hash_val + ord(c)) & 0xFFFFFFFF
    return hash_val

try:
    from z3 import *
    
    target = 0x72d59e59
    initial = 0x1505
    
    print("Using Z3 to find readable flag...")
    print(f"Target hash: 0x{target:x}\n")
    
    # Try different lengths, prioritizing longer ones
    for length in range(20, 35):
        print(f"Trying length {length}...")
        s = Solver()
        
        # Create character variables
        chars = [BitVec(f'c{i}', 8) for i in range(length)]
        
        # Constraints: printable ASCII, prefer readable characters
        for i, c in enumerate(chars):
            # Allow all printable, but prefer alphanumeric and common punctuation
            if i < 3:
                # First 3 chars should be "CS{"
                if i == 0:
                    s.add(c == ord('C'))
                elif i == 1:
                    s.add(c == ord('S'))
                elif i == 2:
                    s.add(c == ord('{'))
            elif i == length - 1:
                # Last char should be '}'
                s.add(c == ord('}'))
            else:
                # Middle chars: prefer alphanumeric, underscore, dash
                # Allow: a-z, A-Z, 0-9, _, -
                s.add(Or(
                    And(c >= ord('a'), c <= ord('z')),
                    And(c >= ord('A'), c <= ord('Z')),
                    And(c >= ord('0'), c <= ord('9')),
                    c == ord('_'),
                    c == ord('-'),
                    c == ord(' ')
                ))
        
        # Hash calculation
        hash_val = BitVecVal(initial, 32)
        for c in chars:
            hash_val = hash_val * BitVecVal(33, 32) + ZeroExt(24, c)
            hash_val = hash_val & BitVecVal(0xFFFFFFFF, 32)
        
        # Target hash
        s.add(hash_val == BitVecVal(target, 32))
        
        # Try to find solution
        if s.check() == sat:
            model = s.model()
            result = ''.join(chr(model[c].as_long()) for c in chars)
            result = result.rstrip('\x00').rstrip()
            
            print(f"\n[+] FOUND FLAG: {result}")
            print(f"[+] Length: {len(result)} characters")
            print(f"[+] Verification: 0x{hash_string(result):08x}")
            if hash_string(result) == target:
                print("[+] ✓ CORRECT!")
            break
        else:
            print(f"  No solution for length {length}")
    
except ImportError:
    print("Z3 not available. Install with: pip3 install z3-solver")
    print("\nTrying alternative approach...")
    
    # Fallback: try common readable patterns
    target = 0x72d59e59
    patterns = [
        "CS{reverse engineering challenge}",
        "CS{hash reversal is fun}",
        "CS{malware reverse engineering}",
        "CS{find the correct flag}",
        "CS{reverse this hash value}",
    ]
    
    for pattern in patterns:
        h = hash_string(pattern)
        if h == target:
            print(f"[+] FOUND: {pattern}")
            break


