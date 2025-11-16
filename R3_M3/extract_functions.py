#!/usr/bin/env python3
"""
Extract and analyze the orbit functions
"""

import subprocess
import re

def extract_functions():
    """Extract function disassembly"""
    result = subprocess.run(['objdump', '-d', 'reMe/reMe.ks'], 
                          capture_output=True, text=True)
    return result.stdout

def find_function_addresses(disasm):
    """Find addresses of orbit functions"""
    funcs = {}
    for func in ['orbit_mist', 'orbit_ember', 'orbit_tide', 'orbit_quartz', 
                 'orbit_haze', 'orbit_nova']:
        pattern = rf'<{func}>:'
        match = re.search(pattern, disasm)
        if match:
            # Get the address from the line before
            lines = disasm[:match.start()].split('\n')
            for line in reversed(lines[-10:]):
                if 'Disassembly' in line or ':' in line:
                    addr_match = re.search(r'([0-9a-f]+)\s+<', line)
                    if addr_match:
                        funcs[func] = int(addr_match.group(1), 16)
                        break
    return funcs

def extract_function_body(disasm, func_name):
    """Extract the body of a function"""
    pattern = rf'<{func_name}>:'
    match = re.search(pattern, disasm)
    if not match:
        return None
    
    start = match.start()
    # Find the next function or section
    next_func = re.search(r'\n[0-9a-f]+\s+<[^>]+>:\n', disasm[start+100:])
    if next_func:
        end = start + 100 + next_func.start()
    else:
        end = start + 500
    
    return disasm[start:end]

def main():
    disasm = extract_functions()
    
    # Find function addresses
    funcs = find_function_addresses(disasm)
    print("=== Function Addresses ===")
    for name, addr in funcs.items():
        print(f"  {name}: 0x{addr:x}")
    
    # Extract function bodies
    print("\n=== Function Bodies ===")
    for func_name in ['orbit_mist', 'orbit_ember', 'orbit_tide', 'orbit_quartz', 
                      'orbit_haze', 'orbit_nova']:
        body = extract_function_body(disasm, func_name)
        if body:
            print(f"\n--- {func_name} ---")
            print(body[:500])  # First 500 chars

if __name__ == '__main__':
    main()


