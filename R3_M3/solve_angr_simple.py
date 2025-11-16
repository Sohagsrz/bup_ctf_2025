#!/usr/bin/env python3
"""
Simplified angr approach - just find what input leads to success
"""

import angr
import claripy

def solve():
    print("=== Loading binary ===")
    project = angr.Project('reMe/reMe.ks', auto_load_libs=False)
    
    # Create symbolic input
    flag_length = 50
    flag = claripy.BVS('flag', flag_length * 8)
    
    # Create state
    state = project.factory.entry_state()
    
    # Set stdin
    state.posix.stdin.content = [(flag, flag_length)]
    
    # Find addresses
    # 0x11c4 = "Congrats, you did good reverse :P"
    # 0x11a0 = "Congrats, you did good reverse :D"  
    # 0x114b = "Nope :("
    
    find_addrs = [0x4011c4, 0x4011a0]  # Adjust for PIE base
    avoid_addrs = [0x40114b]
    
    # Try with actual addresses from analysis
    # Main is at 0x401080, so success should be at 0x401080 + offset
    find_addrs = [0x4011c4, 0x4011a0]
    
    print("=== Running symbolic execution ===")
    simgr = project.factory.simulation_manager(state)
    simgr.explore(find=find_addrs, avoid=avoid_addrs)
    
    if simgr.found:
        print(f"Found {len(simgr.found)} solution(s)!")
        for i, found_state in enumerate(simgr.found):
            try:
                input_bytes = found_state.posix.dumps(0)
                # Extract flag
                flag_str = input_bytes.split(b'\x00')[0].decode('ascii', errors='ignore')
                if 'CS{' in flag_str:
                    start = flag_str.find('CS{')
                    end = flag_str.find('}', start)
                    if end != -1:
                        flag = flag_str[start:end+1]
                        print(f"\n🎉 FLAG: {flag}")
                        return flag
                print(f"Solution {i+1}: {flag_str}")
            except Exception as e:
                print(f"Error: {e}")
    else:
        print("No solution found")
        # Try exploring all paths
        print("Exploring all paths...")
        simgr = project.factory.simulation_manager(state)
        simgr.explore()
        print(f"Explored {len(simgr.deadended)} paths")
    
    return None

if __name__ == '__main__':
    flag = solve()
    if flag:
        print(f"\n✅ FLAG FOUND: {flag}")


