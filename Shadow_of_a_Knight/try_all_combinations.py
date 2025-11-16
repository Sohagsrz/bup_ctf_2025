#!/usr/bin/env python3
"""
Try all possible combinations:
- All hex IDs as keys
- All messages
- Look for the longest, cleanest flag
"""
from scapy.all import rdpcap, Raw, TCP
import urllib.parse
import re

packets = rdpcap('capture.pcap')

# Get all data
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

print(f"Unique hex IDs: {len(hex_ids)}")
print(f"Hex messages: {len(hex_messages)}")
print("\nSearching for longest flags...\n")

all_flags = []

# Try each hex ID on each message
for hex_id in sorted(hex_ids):
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
                    
                    # Only keep flags that are mostly alphanumeric and longer
                    if len(flag_content) > 8:
                        alnum_count = sum(1 for c in flag_content if c.isalnum() or c == '_')
                        if alnum_count / len(flag_content) > 0.9:  # 90% alphanumeric
                            all_flags.append((hex_id, i, flag, len(flag_content)))
            except:
                pass
    except:
        pass

if all_flags:
    all_flags.sort(key=lambda x: x[3], reverse=True)
    print(f"Found {len(all_flags)} potential flags\n")
    print("Top 30 flags (by length):")
    print("=" * 80)
    
    seen = set()
    count = 0
    for hex_id, msg, flag, length in all_flags:
        if flag not in seen and length > 10:  # Only show flags longer than 10
            seen.add(flag)
            print(f"Hex ID: {hex_id}, Message: {msg}, Length: {length}")
            print(f"  {flag}\n")
            count += 1
            if count >= 30:
                break
    
    if all_flags:
        longest = all_flags[0]
        print("=" * 80)
        print(f"LONGEST FLAG: {longest[2]}")
        print(f"Hex ID: {longest[0]}, Message: {longest[1]}, Length: {longest[3]}")
else:
    print("No flags found")

