#!/usr/bin/env python3
from scapy.all import rdpcap, Raw, TCP
import urllib.parse
import re

packets = rdpcap('capture.pcap')

# Extract hex-encoded POST messages
hex_strings = []
for packet in packets:
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        try:
            raw_data = packet[Raw].load
            if b'POST /secret-messages.php' in raw_data:
                data_str = raw_data.decode('utf-8', errors='ignore')
                if 'message=' in data_str:
                    match = re.search(r'message=([^\s&]+)', data_str)
                    if match:
                        encoded_msg = match.group(1)
                        decoded_msg = urllib.parse.unquote(encoded_msg)
                        if decoded_msg.startswith('43537B'):
                            hex_part = decoded_msg[6:]  # Remove "43537B"
                            hex_strings.append(hex_part)
        except:
            pass

print(f"Found {len(hex_strings)} hex-encoded messages")

# Get first message as test
if hex_strings:
    first_hex = hex_strings[0]
    first_bytes = bytes.fromhex(first_hex)
    print(f"First message: {len(first_bytes)} bytes")
    print(f"Hex: {first_hex[:60]}...")
    
    # Try decrypting with common keys
    keys = [b'knightsquad', b'shadow', b'knight', b'flag', b'secret', b'CS{']
    
    for key in keys:
        # Repeating key XOR
        decrypted = bytes([first_bytes[i] ^ key[i % len(key)] for i in range(len(first_bytes))])
        try:
            decoded = decrypted.decode('utf-8', errors='ignore')
            if 'CS{' in decoded or any(c.isprintable() for c in decoded[:20]):
                print(f"\nKey '{key.decode()}' (repeating XOR): {decoded[:100]}")
        except:
            pass

# Try combining all and decrypting
print("\n" + "=" * 80)
print("COMBINING ALL AND TRYING DECRYPTION")
print("=" * 80)

all_hex = ''.join(hex_strings)
all_bytes = bytes.fromhex(all_hex)

for key in [b'knightsquad', b'shadow', b'knight']:
    decrypted = bytes([all_bytes[i] ^ key[i % len(key)] for i in range(min(500, len(all_bytes)))])
    try:
        decoded = decrypted.decode('utf-8', errors='ignore')
        if 'CS{' in decoded:
            flag_match = re.search(r'CS\{[^}]+\}', decoded)
            if flag_match:
                print(f"\nFLAG FOUND with key '{key.decode()}': {flag_match.group(0)}")
        elif any(c.isprintable() for c in decoded[:100]):
            print(f"\nKey '{key.decode()}' (first 200 chars): {decoded[:200]}")
    except:
        pass

