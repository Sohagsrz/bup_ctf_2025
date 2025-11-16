#!/usr/bin/env python3
"""
Reverse the twist_block function to find the secret input
"""

# Bucket root data (29 bytes)
BUCKET_ROOT = bytes.fromhex('8729bd38a1de74707e01a544915154cf909398dd24bec96b695fea71e2')

# Kdata (24 32-bit integers)
KDATA = [
    0xa3d94f21, 0x55ccaa01, 0x12345678, 0xdeadbeef,
    0x0f1e2d3c, 0xcafebabe, 0xfeedface, 0x01020304,
    0x89abcdef, 0x13579bdf, 0x2468ace0, 0x0badf00d,
    0x31415926, 0x27182818, 0xb16b00b5, 0x0c0ffee0,
    0xf00dbaaa, 0xbaadf00d, 0xabcd1234, 0x0defaced,
    0xc001d00d, 0xfeedf00d, 0xdeadc0de, 0x1337c0de
]

# Key for final check
KEY = 0x28c


def twist_block_forward(input_data, key):
    """
    Forward twist_block implementation based on assembly analysis
    This is a simplified version - the actual function is more complex
    """
    data = bytearray(input_data)
    length = len(data)
    
    # First phase: process each byte
    for i in range(length):
        # Calculate index into kdata
        # This is a complex calculation from assembly
        idx = i % 24
        kdata_val = KDATA[idx]
        
        # Shift based on position
        shift = (i * 5) & 0xf
        kdata_shifted = kdata_val >> shift
        
        # XOR with previous byte (or 0 for first)
        if i > 0:
            data[i] ^= data[i-1]
        data[i] ^= (kdata_shifted & 0xff)
        
        # Add key shifted
        key_shift = (key >> (i & 3)) & 0xff
        data[i] = (data[i] + key_shift) & 0xff
        
        # Rotate left by 3
        data[i] = ((data[i] << 3) | (data[i] >> 5)) & 0xff
    
    # Second phase: more processing
    # This is simplified - actual function has more steps
    for i in range(length):
        idx = (i * 3) % 24
        kdata_val = KDATA[idx]
        shift = (i * 7) & 0x7
        kdata_shifted = kdata_val >> shift
        
        data[i] ^= (kdata_shifted & 0xff)
        data[i] = (data[i] + key) & 0xff
        key = (key + 0xb) & 0xffff
        data[i] = ((data[i] << 1) | (data[i] >> 7)) & 0xff
    
    # Third phase: mixing
    # Simplified version
    for i in range(length - 1, 0, -1):
        j = i % length
        k = (i - 1) % length
        val1 = data[j]
        val2 = data[k]
        combined = ((val1 << 5) | (val2 >> 3)) & 0xff
        data[i] ^= combined
    
    return bytes(data)


def reverse_twist_block(output_data, key):
    """
    Reverse the twist_block operation
    This is a simplified attempt - may need refinement
    """
    data = bytearray(output_data)
    length = len(data)
    
    # Reverse phase 3
    for i in range(1, length):
        j = i % length
        k = (i - 1) % length
        val1 = data[j]
        val2 = data[k]
        combined = ((val1 << 5) | (val2 >> 3)) & 0xff
        data[i] ^= combined
    
    # Reverse phase 2
    key_accum = key + (length * 0xb)
    for i in range(length - 1, -1, -1):
        idx = (i * 3) % 24
        kdata_val = KDATA[idx]
        shift = (i * 7) & 0x7
        kdata_shifted = kdata_val >> shift
        
        data[i] = ((data[i] >> 1) | (data[i] << 7)) & 0xff
        key_accum = (key_accum - 0xb) & 0xffff
        data[i] = (data[i] - key_accum) & 0xff
        data[i] ^= (kdata_shifted & 0xff)
    
    # Reverse phase 1
    for i in range(length - 1, -1, -1):
        # Rotate right by 3
        data[i] = ((data[i] >> 3) | (data[i] << 5)) & 0xff
        
        # Subtract key shifted
        key_shift = (key >> (i & 3)) & 0xff
        data[i] = (data[i] - key_shift) & 0xff
        
        # XOR with kdata
        idx = i % 24
        kdata_val = KDATA[idx]
        shift = (i * 5) & 0xf
        kdata_shifted = kdata_val >> shift
        data[i] ^= (kdata_shifted & 0xff)
        
        # XOR with previous byte
        if i > 0:
            data[i] ^= data[i-1]
    
    return bytes(data)


def brute_force_approach():
    """
    Since reversing is complex, try brute forcing with constraints
    """
    # The input should be printable ASCII, likely flag format CS{...}
    # Length is 29 bytes
    # Try common patterns
    
    # Try reversing the twist
    try:
        result = reverse_twist_block(BUCKET_ROOT, KEY)
        print(f"Reversed result (hex): {result.hex()}")
        print(f"Reversed result (ascii): {result}")
        if all(32 <= b < 127 for b in result):
            print(f"Possible flag: {result.decode('ascii', errors='ignore')}")
            return result
    except Exception as e:
        print(f"Error in reverse: {e}")
    
    return None


if __name__ == "__main__":
    print("Attempting to reverse twist_block...")
    print(f"Bucket root: {BUCKET_ROOT.hex()}")
    print(f"Key: 0x{KEY:x}")
    print()
    
    result = brute_force_approach()
    
    if result:
        print(f"\n🎉 Found potential secret: {result}")
    else:
        print("\n❌ Could not reverse. Need to implement full twist_block first.")

