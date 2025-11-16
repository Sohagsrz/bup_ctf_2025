#!/usr/bin/env python3
from scapy.all import rdpcap, Raw, TCP
import urllib.parse
import re

packets = rdpcap('capture.pcap')

# Extract both knight messages and hex-encoded messages with timestamps
knight_messages = []
hex_messages = []

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
                        timestamp = float(packet.time)
                        
                        if decoded_msg.startswith('43537B'):
                            hex_messages.append((timestamp, decoded_msg))
                        else:
                            # Knight message - extract hex ID
                            msg_match = re.match(r'\[[^\]]+\]\[[^\]]+\]\[([^\]]+)\]', decoded_msg)
                            if msg_match:
                                hex_id = msg_match.group(1)
                                knight_messages.append((timestamp, hex_id))
        except:
            pass

# Sort by timestamp
knight_messages.sort(key=lambda x: x[0])
hex_messages.sort(key=lambda x: x[0])

print(f"Found {len(knight_messages)} knight messages")
print(f"Found {len(hex_messages)} hex-encoded messages")

# Try using hex IDs as keys for nearby hex messages
print("\n" + "=" * 80)
print("TRYING HEX IDs AS KEYS FOR HEX MESSAGES")
print("=" * 80)

for i, (hex_time, hex_msg) in enumerate(hex_messages[:20], 1):  # First 20
    # Find closest knight message
    closest_knight = min(knight_messages, key=lambda x: abs(x[0] - hex_time))
    hex_id = closest_knight[1]
    
    # Use hex ID as key
    try:
        key_bytes = bytes.fromhex(hex_id)
        msg_bytes = bytes.fromhex(hex_msg)
        
        # Repeating key XOR
        decrypted = bytes([msg_bytes[j] ^ key_bytes[j % len(key_bytes)] for j in range(len(msg_bytes))])
        decoded = decrypted.decode('utf-8', errors='ignore')
        
        if 'CS{' in decoded:
            flag_match = re.search(r'CS\{[^}]+\}', decoded)
            if flag_match:
                print(f"\nMessage {i} with hex ID {hex_id}:")
                print(f"FLAG FOUND: {flag_match.group(0)}")
                break
            else:
                print(f"Message {i} with hex ID {hex_id}: {decoded[:80]}")
    except Exception as e:
        pass

# Also try using hex ID directly as bytes (not hex-decoded)
print("\n" + "=" * 80)
print("TRYING HEX IDs AS BYTE KEYS (NOT HEX-DECODED)")
print("=" * 80)

for i, (hex_time, hex_msg) in enumerate(hex_messages[:20], 1):
    closest_knight = min(knight_messages, key=lambda x: abs(x[0] - hex_time))
    hex_id = closest_knight[1]
    
    try:
        key_bytes = hex_id.encode('utf-8')
        msg_bytes = bytes.fromhex(hex_msg)
        
        decrypted = bytes([msg_bytes[j] ^ key_bytes[j % len(key_bytes)] for j in range(len(msg_bytes))])
        decoded = decrypted.decode('utf-8', errors='ignore')
        
        if 'CS{' in decoded:
            flag_match = re.search(r'CS\{[^}]+\}', decoded)
            if flag_match:
                print(f"\nMessage {i} with hex ID {hex_id}:")
                print(f"FLAG FOUND: {flag_match.group(0)}")
                break
    except:
        pass

