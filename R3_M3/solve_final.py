#!/usr/bin/env python3
"""
Final solver using angr with fgets hook
"""

import angr
import claripy

def solve():
    print("=== Final Angr Solver ===")
    project = angr.Project('reMe/reMe.ks', auto_load_libs=False)
    
    # Hook fgets to provide our symbolic input
    class FgetsHook(angr.SimProcedure):
        def run(self, buf, size, file_ptr):
            # Create symbolic input
            symbolic_input = claripy.BVS('input', 256 * 8)
            
            # Add constraints: should be printable ASCII and start with CS{
            for i in range(min(256, 50)):
                if i < 3:
                    # First 3 chars: "CS{"
                    self.state.solver.add(symbolic_input.get_byte(i) == [ord('C'), ord('S'), ord('{')][i])
                else:
                    # Rest: printable ASCII or }
                    byte = symbolic_input.get_byte(i)
                    self.state.solver.add(
                        claripy.Or(
                            claripy.And(byte >= 32, byte <= 126),  # Printable
                            byte == ord('}'),
                            byte == 0  # Null terminator
                        )
                    )
            
            # Copy to buffer
            self.state.memory.store(buf, symbolic_input)
            
            # Return pointer to buffer (simulating fgets behavior)
            # Find the length (up to first null or size-1)
            return buf
    
    # Hook fgets
    project.hook_symbol('fgets', FgetsHook())
    
    # Create entry state
    state = project.factory.entry_state()
    
    # Find success addresses
    # From analysis: main is at 0x1080
    # Success at 0x11c4 and 0x11a0
    # But with PIE, these might be different
    # Let's use the strings to find the addresses
    cfg = project.analyses.CFG()
    
    # Find puts calls that print success messages
    # "Congrats, you did good reverse :P" at 0x2010
    # "Congrats, you did good reverse :D" at 0x2038
    
    # Try to find these addresses in the binary
    find_strings = [
        b"Congrats, you did good reverse :P",
        b"Congrats, you did good reverse :D"
    ]
    
    # Get the addresses from the binary
    with open('reMe/reMe.ks', 'rb') as f:
        data = f.read()
    
    find_addrs = []
    for s in find_strings:
        idx = data.find(s)
        if idx != -1:
            # Find references to this string
            # The string is at offset idx, need to find code that references it
            print(f"Found string at offset 0x{idx:x}")
    
    # Use known offsets from analysis
    # Main is at 0x1080, success paths are at 0x11c4 and 0x11a0
    # But with PIE, base might be different
    # Let's try with the actual addresses from the binary
    
    print("=== Running symbolic execution ===")
    simgr = project.factory.simulation_manager(state)
    
    # Explore with a timeout
    import signal
    
    def timeout_handler(signum, frame):
        raise TimeoutError("Symbolic execution timed out")
    
    # Try exploring
    try:
        # Find addresses that call puts with success strings
        # This is complex, let's try a simpler approach
        
        # Just explore and look for states that have our input
        simgr.explore()
        
        if simgr.found:
            print(f"Found {len(simgr.found)} states")
        elif simgr.deadended:
            print(f"Explored {len(simgr.deadended)} paths")
            # Check deadended states for potential solutions
            for state in simgr.deadended[:10]:  # Check first 10
                try:
                    # Try to get input from stdin
                    # This is complex without knowing the exact state structure
                    pass
                except:
                    pass
    except Exception as e:
        print(f"Error during exploration: {e}")
        import traceback
        traceback.print_exc()
    
    return None

if __name__ == '__main__':
    result = solve()
    if result:
        print(f"\n🎉 FLAG: {result}")


