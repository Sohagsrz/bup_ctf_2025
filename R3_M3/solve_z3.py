#!/usr/bin/env python3
"""
Use Z3 to solve for the flag by reversing the hash functions
"""

from z3 import *
import struct

# Constants
DRIFT_TABLE = [
    0x8a5d83122b9fc028,
    0xe90048615824641b,
    0x272bf6e58d019afd,
    0x8442a9360163fb96,
    0xe0cba1e41a4c2046
]

XOR_KEY = 0xC3B1E37F9A4D2605
FINAL_CHECK = 0xFCE62D194453D523

# Expected hashes (XORed drift_table values)
EXPECTED_HASHES = [d ^ XOR_KEY for d in DRIFT_TABLE]

def solve_with_z3():
    """Try to solve using Z3"""
    print("=== Z3 Solver ===")
    print(f"Expected hashes (after XOR):")
    for i, h in enumerate(EXPECTED_HASHES):
        print(f"  [{i}] = 0x{h:016x}")
    
    # This is complex - the hash functions are non-linear
    # Let's try a simpler approach: brute force with constraints
    
    print("\nNote: Z3 solving for complex hash functions is difficult.")
    print("Trying alternative approach...")

def try_common_flags():
    """Try common flag patterns"""
    common_patterns = [
        "CS{flag}",
        "CS{test}",
        "CS{something_her3}",
        "CS{R3_M3}",
        "CS{r3m3}",
        "CS{reverse_me}",
        "CS{reverse}",
    ]
    
    print("\n=== Trying Common Patterns ===")
    for pattern in common_patterns:
        print(f"Trying: {pattern}")

if __name__ == '__main__':
    solve_with_z3()
    try_common_flags()


