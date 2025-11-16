#!/usr/bin/env python3
"""
Try ALL hex IDs from knight messages as keys for ALL hex-encoded messages
"""
from scapy.all import rdpcap, Raw, TCP
import urllib.parse
import re

packets = rdpcap('capture.pcap')

# Get all hex IDs and hex messages
hex_ids = set()
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
                        
                        if decoded_msg.startswith('43537B'):
                            hex_messages.append(decoded_msg)
                        else:
                            msg_match = re.match(r'\[[^\]]+\]\[[^\]]+\]\[([^\]]+)\]', decoded_msg)
                            if msg_match:
                                hex_ids.add(msg_match.group(1))
        except:
            pass

print(f"Found {len(hex_ids)} unique hex IDs")
print(f"Found {len(hex_messages)} hex-encoded messages")

# Try each hex ID as key for each hex message
print("\nTrying all hex IDs as keys...")
print("This may take a moment...\n")

found_flags = []
for hex_id in sorted(hex_ids):
    try:
        key_bytes = bytes.fromhex(hex_id)
        
        for i, hex_str in enumerate(hex_messages[:100], 1):  # First 100 for speed
            try:
                msg_bytes = bytes.fromhex(hex_str)
                encrypted_part = msg_bytes[3:]
                
                decrypted = bytes([encrypted_part[j] ^ key_bytes[j % len(key_bytes)] for j in range(len(encrypted_part))])
                decoded = decrypted.decode('utf-8', errors='ignore')
                full_flag = 'CS{' + decoded
                
                flag_match = re.search(r'CS\{[A-Za-z0-9_]+\}', full_flag)
                if flag_match:
                    flag = flag_match.group(0)
                    flag_content = flag[3:-1]
                    
                    # Check if it's a good flag (long, alphanumeric)
                    if len(flag_content) > 10 and all(c.isalnum() or c == '_' for c in flag_content):
                        found_flags.append((hex_id, i, flag, len(flag)))
                        print(f"Hex ID {hex_id}, Message {i}: {flag} (length: {len(flag)})")
            except:
                pass
    except:
        pass

if found_flags:
    print(f"\n\nFound {len(found_flags)} potential flags")
    # Sort by length
    found_flags.sort(key=lambda x: x[3], reverse=True)
    print("\nLongest flags:")
    for hex_id, msg, flag, length in found_flags[:10]:
        print(f"  {flag} (Hex ID: {hex_id}, Message: {msg})")
else:
    print("\nNo flags found with hex IDs as keys")

