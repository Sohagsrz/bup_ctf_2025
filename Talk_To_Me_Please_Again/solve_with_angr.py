#!/usr/bin/env python3
"""
Try using angr to solve this symbolically
"""

try:
    import angr
    import claripy
    
    BUCKET_ROOT = bytes.fromhex('8729bd38a1de74707e01a544915154cf909398dd24bec96b695fea71e2')
    KEY = 0x28c
    
    print("Loading binary with angr...")
    project = angr.Project('./TTMPA/ttmpa.ks', auto_load_libs=False)
    
    # Find the main function
    print("Finding main function...")
    main_addr = project.loader.find_symbol('main')
    if main_addr:
        print(f"Main at: 0x{main_addr.rebased_addr:x}")
    
    # Create symbolic input
    input_len = 29
    flag_chars = [claripy.BVS(f'flag_{i}', 8) for i in range(input_len)]
    flag = claripy.Concat(*flag_chars)
    
    # Add constraints: printable ASCII, starts with "CS{", ends with "}"
    for i, char in enumerate(flag_chars):
        if i < 3:
            # First 3 chars: "CS{"
            if i == 0:
                solver.add(char == ord('C'))
            elif i == 1:
                solver.add(char == ord('S'))
            elif i == 2:
                solver.add(char == ord('{'))
        elif i == input_len - 1:
            # Last char: "}"
            solver.add(char == ord('}'))
        else:
            # Middle chars: printable ASCII
            solver.add(char >= 32, char < 127)
    
    print("Setting up symbolic execution...")
    # This is complex - would need to set up state and explore
    print("Note: Full angr setup requires more configuration")
    print("Trying alternative approach...")
    
except ImportError:
    print("angr not available")
    print("Trying alternative constraint-based approach...")

# Alternative: Try to use the observation that bucket_1 matches last 13 bytes
# This might give us a clue about the algorithm structure

BUCKET_ROOT = bytes.fromhex('8729bd38a1de74707e01a544915154cf909398dd24bec96b695fea71e2')
BUCKET_1 = bytes.fromhex('909398dd24bec96b695fea71e2')

print(f"\nObservation: bucket_1 matches last 13 bytes of bucket_root")
print(f"bucket_root: {BUCKET_ROOT.hex()}")
print(f"bucket_1:    {BUCKET_1.hex()}")
print(f"Last 13:     {BUCKET_ROOT[-13:].hex()}")
print(f"Match: {BUCKET_1 == BUCKET_ROOT[-13:]}")

# This suggests the algorithm might process in chunks
# Or that bucket_1 is an intermediate result

print("\nTrying to work backwards from this observation...")

