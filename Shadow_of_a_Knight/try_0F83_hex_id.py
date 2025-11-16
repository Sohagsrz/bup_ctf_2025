#!/usr/bin/env python3
"""
Try hex ID 0F83 (from message mentioning 'the key is never in the lock') on all hex messages
"""
from scapy.all import rdpcap, Raw, TCP
import urllib.parse
import re

packets = rdpcap('capture.pcap')

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
        except:
            pass

# Try hex ID 0F83
hex_id = '0F83'
key = bytes.fromhex(hex_id)

print(f'Checking all {len(hex_messages)} messages with hex ID {hex_id}...')
print('Looking for flags longer than 12 characters...\n')

results = []
for i, hex_str in enumerate(hex_messages, 1):
    try:
        msg_bytes = bytes.fromhex(hex_str)
        encrypted_part = msg_bytes[3:]
        decrypted = bytes([encrypted_part[j] ^ key[j % len(key)] for j in range(len(encrypted_part))])
        decoded = decrypted.decode('utf-8', errors='ignore')
        full_flag = 'CS{' + decoded
        
        flag_match = re.search(r'CS\{[A-Za-z0-9_]+\}', full_flag)
        if flag_match:
            flag = flag_match.group(0)
            flag_content = flag[3:-1]
            if len(flag_content) > 12:
                alnum = sum(1 for c in flag_content if c.isalnum() or c == '_')
                if alnum / len(flag_content) > 0.9:
                    results.append((i, flag, len(flag_content)))
    except:
        pass

if results:
    results.sort(key=lambda x: x[2], reverse=True)
    print(f'Found {len(results)} flags longer than 12 chars:\n')
    for msg, flag, length in results[:10]:
        print(f'Message {msg}: {flag} (length: {length})')
else:
    print('No flags longer than 12 characters found with hex ID 0F83')

