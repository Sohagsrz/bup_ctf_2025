#!/usr/bin/env python3
"""
Analyze the lanes array to understand the function mapping
"""

import struct

# Function addresses from disassembly
FUNCTIONS = {
    'orbit_mist': 0x1300,
    'orbit_ember': 0x13b0,
    'orbit_tide': 0x1470,
    'orbit_quartz': 0x1620,
    'orbit_haze': 0x1710,
    'orbit_nova': 0x17d0,
}

def analyze_lanes():
    with open('reMe/reMe.ks', 'rb') as f:
        data = f.read()
    
    offset = 0x3da0
    lanes = []
    for i in range(5):
        val = struct.unpack('<Q', data[offset + i*8:offset + i*8 + 8])[0]
        lanes.append(val)
    
    print("=== Lanes Analysis ===")
    for i, val in enumerate(lanes):
        print(f"lanes[{i}] = 0x{val:016x}")
        
        # Try different interpretations
        if val == 0:
            print(f"  -> NULL/zero")
        elif val == 1:
            print(f"  -> Could be index 1 or flag")
        elif val == 0x200000001:
            # Split into two 32-bit values
            low = val & 0xFFFFFFFF
            high = (val >> 32) & 0xFFFFFFFF
            print(f"  -> Split: low=0x{low:x} ({low}), high=0x{high:x} ({high})")
        elif val == 0x3050:
            print(f"  -> Offset 0x3050")
            # Check if this could be a function address
            base = 0x1000
            possible_addr = base + 0x3050
            print(f"     If base=0x{base:x}, would be 0x{possible_addr:x}")
            # Check what's at that address
            if possible_addr < len(data):
                print(f"     Data at 0x{possible_addr:x}: {data[possible_addr:possible_addr+16].hex()}")
    
    # Check if lanes[1] = 0x200000001 could be two function pointers
    # Maybe it's stored as two 32-bit values?
    print("\n=== Alternative Interpretation ===")
    print("Maybe lanes is stored as 32-bit values?")
    offset = 0x3da0
    for i in range(10):  # 10 32-bit values
        val = struct.unpack('<I', data[offset + i*4:offset + i*4 + 4])[0]
        print(f"  lanes_32[{i}] = 0x{val:08x} ({val})")
        if val in FUNCTIONS.values():
            for name, addr in FUNCTIONS.items():
                if addr == val:
                    print(f"    -> Matches {name}!")
        elif val > 0x1000 and val < 0x2000:
            print(f"    -> Possible function address: 0x{val:x}")

if __name__ == '__main__':
    analyze_lanes()


