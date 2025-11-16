#!/usr/bin/env python3
"""
Process hex messages: Remove 43537B prefix, decrypt, and combine
43537B = CS{ in hex, 7D = } in hex
"""

# Sample hex messages from user (first few)
hex_messages = [
    '43537B2ff3b09cadea56c182af433478513eb16ee1d8e786b789b7',
    '43537Bb3a42684210d82f317be60efddaba518e71aee540de76377',
    '43537B23694088773b0d5eb15c80657aefd89b465f19fda1baae65',
    '43537B4e4280203ab1f684e75f985e0c3709e3d95814073f5de0d0',
    '43537B28dc0e87fb29fc7814dd6736fd71c5d425162c631fb0f1e0',
]

# Hex IDs from knight messages (sample)
hex_ids = ['0E8F', '42CE', '4E01', '31A3', '0F83', '1062', '24AC']

print("Processing hex messages...")
print(f"Number of messages: {len(hex_messages)}")
print(f"Number of hex IDs to try: {len(hex_ids)}\n")

for hex_id in hex_ids:
    try:
        key = bytes.fromhex(hex_id)
        combined_bytes = b''
        
        for hex_str in hex_messages:
            # Remove 43537B prefix (CS{)
            hex_part = hex_str[6:]
            msg_bytes = bytes.fromhex(hex_part)
            # Decrypt with XOR
            decrypted = bytes([msg_bytes[i] ^ key[i % len(key)] for i in range(len(msg_bytes))])
            combined_bytes += decrypted
        
        # Decode to text
        combined_text = combined_bytes.decode('utf-8', errors='ignore')
        
        # Check readability
        printable = sum(1 for c in combined_text if 32 <= ord(c) <= 126)
        if len(combined_text) > 0:
            ratio = printable / len(combined_text)
            if ratio > 0.6:
                print(f"Hex ID {hex_id}:")
                print(f"  Combined length: {len(combined_text)}")
                print(f"  Printable ratio: {ratio:.2%}")
                print(f"  Content: {combined_text[:100]}...")
                if 'CS{' in combined_text or any(c.isalpha() for c in combined_text[:50]):
                    print(f"  *** POTENTIAL FLAG CONTENT ***")
                print()
    except Exception as e:
        pass

