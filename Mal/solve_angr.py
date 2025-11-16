#!/usr/bin/env python3
"""
Try using angr for symbolic execution to find the flag
"""

try:
    import angr
    import claripy
    
    print("Loading binary with angr...")
    project = angr.Project('mal.ks', auto_load_libs=False)
    
    # Find the main function
    print("Finding main function...")
    main_addr = project.loader.find_symbol('main').rebased_addr
    print(f"Main at: 0x{main_addr:x}")
    
    # Create initial state
    state = project.factory.entry_state()
    
    # Create symbolic input (flag)
    flag_length = 20
    flag = claripy.BVS('flag', 8 * flag_length)
    
    # Constrain to printable ASCII
    for i in range(flag_length):
        state.solver.add(flag.get_byte(i) >= 0x20)
        state.solver.add(flag.get_byte(i) < 0x7f)
    
    # Find the hash comparison
    target_hash = 0x72d59e59
    
    print("Starting symbolic execution...")
    simgr = project.factory.simgr(state)
    simgr.explore(find=lambda s: b"Correct flag" in s.posix.dumps(1))
    
    if simgr.found:
        print("\n[+] Found solution!")
        solution_state = simgr.found[0]
        flag_bytes = solution_state.solver.eval(flag, cast_to=bytes)
        flag_str = flag_bytes.decode('utf-8', errors='ignore').rstrip('\x00')
        print(f"Flag: {flag_str}")
    else:
        print("[-] Could not find solution with angr")
        
except ImportError:
    print("angr not available. Install with: pip install angr")
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()


