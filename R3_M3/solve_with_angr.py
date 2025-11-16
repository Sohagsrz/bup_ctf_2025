#!/usr/bin/env python3
"""
Use angr to solve the challenge symbolically
"""

import angr
import sys
import os

# Path to binary
binary_path = 'reMe/reMe.ks'

if not os.path.exists(binary_path):
    print(f"Binary not found at {binary_path}")
    sys.exit(1)

print("Loading binary with angr...")
proj = angr.Project(binary_path, auto_load_libs=False)

# Find the main function
print("Finding main function...")
main_addr = proj.loader.find_symbol('main')
if main_addr:
    print(f"Main at: {hex(main_addr.rebased_addr)}")
    entry = main_addr.rebased_addr
else:
    entry = proj.entry
    print(f"Using entry point: {hex(entry)}")

# Find success addresses
print("Finding success addresses...")
success_addrs = []
for addr, name in proj.loader.find_all_symbols('main'):
    pass

# Look for the success strings
strings = proj.loader.main_object.search(b'Congrats')
for addr in strings:
    print(f"Found 'Congrats' at: {hex(addr)}")
    # Find the function that references this
    cfg = proj.analyses.CFG()
    for func in cfg.functions.values():
        if addr in func.block_addrs_set:
            print(f"  In function at: {hex(func.addr)}")
            # Find basic blocks that might lead here
            for block in func.blocks:
                if addr in [x for x in block.instruction_addrs]:
                    success_addrs.append(block.addr)
                    print(f"    Success block at: {hex(block.addr)}")

if not success_addrs:
    # Try to find by searching for the string in the binary
    print("Searching for success strings...")
    with open(binary_path, 'rb') as f:
        data = f.read()
        idx = data.find(b'Congrats')
        if idx != -1:
            print(f"Found 'Congrats' at offset: {hex(idx)}")
            # This is in .rodata, find what references it
            # For now, let's use a different approach

# Create initial state
print("Creating initial state...")
state = proj.factory.entry_state()

# Find stdin or input reading
# The binary likely reads from stdin
# Let's create symbolic input
print("Creating symbolic input...")
# Assume input is read via gets or similar
# We need to find where input is read

# Try a simpler approach: find where input is compared
print("Searching for comparison operations...")

# Actually, let's use a more direct approach
# Find the function that does the hash checking
print("Attempting to find hash checking logic...")

# For now, let's try to explore from entry
print("Starting symbolic execution...")
simgr = proj.factory.simulation_manager(state)

# Explore until we find success
print("Exploring paths...")
simgr.explore(find=success_addrs if success_addrs else None)

if simgr.found:
    print(f"\n✓ Found solution!")
    found_state = simgr.found[0]
    # Extract the input
    # The input is likely in stdin or a buffer
    # Let's check stdin
    stdin = found_state.posix.stdin.load(0, 100)
    flag = found_state.solver.eval(stdin, cast_to=bytes)
    print(f"Flag: {flag.decode('utf-8', errors='ignore')}")
else:
    print("\n✗ No solution found")
    print("Trying different approach...")


