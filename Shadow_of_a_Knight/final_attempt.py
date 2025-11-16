#!/usr/bin/env python3
from scapy.all import rdpcap, Raw, TCP, DNS
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
                            hex_part = decoded_msg[6:]
                            hex_strings.append(hex_part)
        except:
            pass

# Extract hex IDs from knight messages
hex_ids = []
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
                        if not decoded_msg.startswith('43537B'):
                            msg_match = re.match(r'\[[^\]]+\]\[[^\]]+\]\[([^\]]+)\]', decoded_msg)
                            if msg_match:
                                hex_ids.append(msg_match.group(1))
        except:
            pass

print(f"Found {len(hex_strings)} hex-encoded messages")
print(f"Found {len(hex_ids)} hex IDs from knight messages")

# Try using hex IDs as key
if hex_ids and hex_strings:
    # Combine hex IDs to form a key
    key_hex = ''.join(hex_ids)
    try:
        key_bytes = bytes.fromhex(key_hex)
        print(f"\nKey from hex IDs: {len(key_bytes)} bytes")
        
        # Try decrypting first few hex messages with this key
        for i, hex_str in enumerate(hex_strings[:5], 1):
            msg_bytes = bytes.fromhex(hex_str)
            # Repeating key XOR
            decrypted = bytes([msg_bytes[j] ^ key_bytes[j % len(key_bytes)] for j in range(len(msg_bytes))])
            try:
                decoded = decrypted.decode('utf-8', errors='ignore')
                if 'CS{' in decoded or any(c.isprintable() for c in decoded):
                    print(f"\nMessage {i} decrypted: {decoded[:100]}")
            except:
                pass
    except:
        pass

# Also try combining all hex strings and looking for patterns
print("\n" + "=" * 80)
print("COMBINING ALL HEX STRINGS")
print("=" * 80)

all_hex = ''.join(hex_strings)
all_bytes = bytes.fromhex(all_hex)

# Try to find readable text by looking at byte patterns
# Maybe it's not encrypted, just needs to be read differently
print(f"Total bytes: {len(all_bytes)}")

# Check if there are any readable ASCII sequences
readable_chunks = []
for i in range(0, len(all_bytes) - 10, 1):
    chunk = all_bytes[i:i+50]
    try:
        decoded = chunk.decode('utf-8', errors='ignore')
        if 'CS{' in decoded:
            flag_match = re.search(r'CS\{[^}]+\}', decoded)
            if flag_match:
                print(f"\nFLAG FOUND at offset {i}: {flag_match.group(0)}")
                break
    except:
        pass

# Also try looking at the data in reverse
print("\nTrying reverse order...")
reversed_bytes = all_bytes[::-1]
for i in range(0, len(reversed_bytes) - 10, 1):
    chunk = reversed_bytes[i:i+50]
    try:
        decoded = chunk.decode('utf-8', errors='ignore')
        if 'CS{' in decoded:
            flag_match = re.search(r'CS\{[^}]+\}', decoded)
            if flag_match:
                print(f"\nFLAG FOUND in reverse at offset {i}: {flag_match.group(0)}")
                break
    except:
        pass

