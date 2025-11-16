#!/usr/bin/env python3
"""
Complete analysis: Extract all hash functions and try to understand lanes mapping
"""

import subprocess
import re

def extract_all_functions():
    """Extract all orbit function implementations"""
    result = subprocess.run(['objdump', '-d', 'reMe/reMe.ks'], 
                          capture_output=True, text=True)
    return result.stdout

def find_function_bodies(disasm):
    """Extract complete function bodies"""
    functions = {}
    func_names = ['orbit_mist', 'orbit_ember', 'orbit_tide', 'orbit_quartz', 'orbit_haze', 'orbit_nova']
    
    for func_name in func_names:
        # Find function start
        pattern = rf'<{func_name}>:'
        match = re.search(pattern, disasm)
        if match:
            start = match.start()
            # Find next function
            next_pattern = r'\n[0-9a-f]+\s+<[^>]+>:\n'
            next_match = re.search(next_pattern, disasm[start+50:])
            if next_match:
                end = start + 50 + next_match.start()
            else:
                end = start + 2000
            functions[func_name] = disasm[start:end]
    
    return functions

def analyze_lanes_mapping():
    """Try to understand how lanes maps to functions"""
    # From the assembly:
    # leaq 0x2ca9(%rip), %r12  # 0x3da0 <lanes.0>
    # callq *(%r12)  # calls function at address in r12
    
    # So lanes[i] should be a function pointer
    # But the values are: [0x1, 0x200000001, 0x0, 0x0, 0x3050]
    
    # Maybe it's a jump table? Or maybe the values are indices?
    # Let's check if there's a function table
    
    print("=== Analyzing lanes mapping ===")
    print("The call instruction: callq *(%r12)")
    print("This calls the function pointer stored at the address in r12")
    print("r12 points to lanes.0 at 0x3da0")
    print("\nPossible interpretations:")
    print("1. lanes[i] contains function pointers (but values don't look like pointers)")
    print("2. lanes[i] contains indices into a function table")
    print("3. lanes[i] contains offsets that need to be added to a base")
    print("4. The structure is different than expected")
    
    # Check if there's a function table
    print("\nChecking for function table...")

def main():
    print("=== Complete Binary Analysis ===")
    
    # Extract functions
    disasm = extract_all_functions()
    functions = find_function_bodies(disasm)
    
    print(f"\nFound {len(functions)} functions:")
    for name in functions.keys():
        print(f"  - {name}")
    
    # Analyze lanes
    analyze_lanes_mapping()
    
    # Try to find patterns
    print("\n=== Looking for patterns ===")
    # Check if any function addresses appear in the binary near lanes
    print("Function addresses:")
    func_addrs = {
        'orbit_mist': 0x1300,
        'orbit_ember': 0x13b0,
        'orbit_tide': 0x1470,
        'orbit_quartz': 0x1620,
        'orbit_haze': 0x1710,
        'orbit_nova': 0x17d0
    }
    
    for name, addr in func_addrs.items():
        print(f"  {name}: 0x{addr:x}")

if __name__ == '__main__':
    main()


