#!/usr/bin/env python3
"""
Use angr to symbolically execute the binary and find the flag
"""

import angr
import claripy

def solve_with_angr():
    """Use angr to solve for the flag"""
    print("=== Loading binary with angr ===")
    
    # Load the binary
    project = angr.Project('reMe/reMe.ks', auto_load_libs=False)
    
    print(f"Binary loaded: {project.filename}")
    print(f"Architecture: {project.arch}")
    
    # Find the main function
    cfg = project.analyses.CFG()
    main_func = cfg.functions.get('main')
    
    if main_func:
        print(f"Found main function at 0x{main_func.addr:x}")
    else:
        print("Main function not found, using entry point")
        main_func = None
    
    # Create symbolic input
    # The input is read via fgets with max 256 bytes
    # But we'll limit it to a reasonable size for the flag
    flag_length = 50  # Reasonable flag length
    flag = claripy.BVS('flag', flag_length * 8)
    
    # Add constraints: flag should start with "CS{" and end with "}"
    # And contain printable ASCII
    constraints = []
    
    # Start with "CS{"
    constraints.append(flag[0] == ord('C'))
    constraints.append(flag[1] == ord('S'))
    constraints.append(flag[2] == ord('{'))
    
    # End with "}"
    # We don't know the exact length, so we'll let angr figure it out
    # But we can add that it should be printable ASCII
    for i in range(3, flag_length - 1):
        constraints.append(
            claripy.Or(
                claripy.And(flag[i] >= ord(' '), flag[i] <= ord('~')),  # Printable ASCII
                flag[i] == ord('}'),  # Or closing brace
                flag[i] == 0  # Or null terminator
            )
        )
    
    # Create initial state
    if main_func:
        entry_state = project.factory.entry_state(addr=main_func.addr)
    else:
        entry_state = project.factory.entry_state()
    
    # Set up stdin with our symbolic flag
    # The program uses fgets(stdin, 256, stdin)
    # Set stdin to our symbolic flag
    entry_state.posix.stdin.content = [(flag, flag_length)]
    
    # Create simulation manager
    simgr = project.factory.simulation_manager(entry_state)
    
    # Find the success states
    # Looking for addresses that print "Congrats"
    # From analysis: 0x11c4 prints "Congrats, you did good reverse :P"
    #                0x11a0 prints "Congrats, you did good reverse :D"
    
    print("\n=== Running symbolic execution ===")
    print("This may take a while...")
    
    # Explore until we find success
    simgr.explore(find=[0x11c4, 0x11a0], avoid=[0x114b])  # avoid the "Nope" path
    
    if simgr.found:
        print(f"\n✓ Found {len(simgr.found)} solution(s)!")
        for i, state in enumerate(simgr.found):
            print(f"\n--- Solution {i+1} ---")
            # Get the input that led to this state
            try:
                input_data = state.posix.dumps(0)
                # Find the flag in the input
                flag_str = input_data.split(b'\x00')[0].decode('ascii', errors='ignore')
                if 'CS{' in flag_str:
                    flag_start = flag_str.find('CS{')
                    flag_end = flag_str.find('}', flag_start)
                    if flag_end != -1:
                        found_flag = flag_str[flag_start:flag_end+1]
                        print(f"FLAG: {found_flag}")
                        return found_flag
                print(f"Input: {flag_str}")
            except Exception as e:
                print(f"Error extracting flag: {e}")
    else:
        print("\n✗ No solution found with current constraints")
        print("Trying alternative approach...")
        
        # Try exploring more paths
        simgr = project.factory.simulation_manager(entry_state)
        simgr.explore()
        
        if simgr.deadended:
            print(f"Explored {len(simgr.deadended)} paths")
    
    return None

if __name__ == '__main__':
    flag = solve_with_angr()
    if flag:
        print(f"\n🎉 FLAG FOUND: {flag}")
    else:
        print("\n❌ Flag not found. May need to adjust constraints or use different approach.")

