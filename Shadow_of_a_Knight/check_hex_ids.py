#!/usr/bin/env python3
from scapy.all import rdpcap, Raw, TCP
import urllib.parse
import re

packets = rdpcap('capture.pcap')

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
                        # Look for knight messages (format: [timestamp][Knight-ID][Hex-ID])
                        if not decoded_msg.startswith('43537B'):
                            msg_match = re.match(r'\[[^\]]+\]\[[^\]]+\]\[([^\]]+)\]', decoded_msg)
                            if msg_match:
                                hex_id = msg_match.group(1)
                                hex_ids.append(hex_id)
        except:
            pass

print(f'Found {len(hex_ids)} hex IDs from knight messages')
print(f'Unique hex IDs: {len(set(hex_ids))}')
print(f'\nFirst 10 hex IDs: {hex_ids[:10]}')

# Try to see if combining them forms something
combined_hex = ''.join(hex_ids)
print(f'\nCombined hex length: {len(combined_hex)}')
print(f'First 100 chars: {combined_hex[:100]}')

# Try to decode
try:
    decoded = bytes.fromhex(combined_hex).decode('utf-8', errors='ignore')
    print(f'\nDecoded (first 200 chars): {decoded[:200]}')
    if 'CS{' in decoded:
        flag_match = re.search(r'CS\{[^}]+\}', decoded)
        if flag_match:
            print(f'\nFLAG FOUND: {flag_match.group(0)}')
except:
    print('Could not decode as hex')

