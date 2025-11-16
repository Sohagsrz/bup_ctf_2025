#!/usr/bin/env python3
"""
Analyze the reMe.ks binary to extract key data structures
"""

import struct

def read_binary():
    with open('reMe/reMe.ks', 'rb') as f:
        return f.read()

def extract_drift_table(data):
    """Extract drift_table values from offset 0x2060"""
    offset = 0x2060
    drift_table = []
    for i in range(5):  # 5 entries based on the loop
        val = struct.unpack('<Q', data[offset + i*8:offset + i*8 + 8])[0]
        drift_table.append(val)
    return drift_table

def extract_lanes(data):
    """Extract function pointers from lanes.0 at offset 0x3da0"""
    offset = 0x3da0
    lanes = []
    for i in range(5):
        val = struct.unpack('<Q', data[offset + i*8:offset + i*8 + 8])[0]
        lanes.append(val)
    return lanes

def find_strings(data):
    """Find important strings"""
    strings = {}
    strings['nope'] = data.find(b'Nope :(')
    strings['congrats1'] = data.find(b'Congrats, you did good reverse :P')
    strings['congrats2'] = data.find(b'Congrats, you did good reverse :D')
    return strings

def main():
    data = read_binary()
    
    print("=== Binary Analysis ===")
    print(f"File size: {len(data)} bytes ({len(data)/1024/1024:.2f} MB)")
    
    # Extract drift_table
    drift_table = extract_drift_table(data)
    print(f"\n=== Drift Table (at 0x2060) ===")
    for i, val in enumerate(drift_table):
        print(f"  [{i}] = 0x{val:016x}")
    
    # Extract lanes
    lanes = extract_lanes(data)
    print(f"\n=== Lanes (function pointers at 0x3da0) ===")
    for i, val in enumerate(lanes):
        print(f"  [{i}] = 0x{val:016x}")
    
    # Find strings
    strings = find_strings(data)
    print(f"\n=== Important Strings ===")
    for name, offset in strings.items():
        if offset != -1:
            print(f"  {name}: offset {hex(offset)}")
            # Extract the string
            end = data.find(b'\x00', offset)
            if end != -1:
                print(f"    '{data[offset:end].decode()}'")
    
    # The XOR key from main
    xor_key = 0xC3B1E37F9A4D2605
    print(f"\n=== XOR Key ===")
    print(f"  0x{xor_key:016x}")
    
    # The final check value
    final_check = 0xFCE62D194453D523
    print(f"\n=== Final Check Value ===")
    print(f"  0x{final_check:016x}")

if __name__ == '__main__':
    main()


