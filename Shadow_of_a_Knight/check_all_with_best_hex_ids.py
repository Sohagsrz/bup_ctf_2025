#!/usr/bin/env python3
"""
Check ALL messages with the hex IDs that gave us flags
"""
from scapy.all import rdpcap, Raw, TCP
import urllib.parse
import re

packets = rdpcap('capture.pcap')

# Get all hex messages
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

# Try hex IDs that gave us results
promising_hex_ids = ['1062', '24AC', '0E8F', '42CE', '4E01', '31A3', '0F83']

print(f"Checking all {len(hex_messages)} messages with promising hex IDs...\n")

all_results = []

for hex_id in promising_hex_ids:
    try:
        key = bytes.fromhex(hex_id)
        
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
                    
                    if len(flag_content) > 8:
                        alnum_count = sum(1 for c in flag_content if c.isalnum() or c == '_')
                        if alnum_count == len(flag_content):  # 100% alphanumeric
                            all_results.append((hex_id, i, flag, len(flag_content)))
            except:
                pass
    except:
        pass

if all_results:
    all_results.sort(key=lambda x: x[3], reverse=True)
    print(f"Found {len(all_results)} clean flags\n")
    print("All results (sorted by length):")
    print("=" * 80)
    
    for hex_id, msg, flag, length in all_results:
        print(f"Hex ID: {hex_id}, Message: {msg}, Length: {length}")
        print(f"  {flag}\n")
    
    # Show longest
    longest = all_results[0]
    print("=" * 80)
    print(f"LONGEST FLAG: {longest[2]}")
    print(f"Hex ID: {longest[0]}, Message: {longest[1]}, Length: {longest[3]}")
else:
    print("No additional flags found")

