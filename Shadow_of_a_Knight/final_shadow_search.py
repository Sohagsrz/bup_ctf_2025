#!/usr/bin/env python3
"""
Final comprehensive search with shadow/no shadow keys
Check ALL messages and find the longest, cleanest flag
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

print(f"Total hex messages: {len(hex_messages)}")

keys = [b'shadow', b'no shadow', b'shadow under moonlight', b'no shadow under moonlight']

print("\nChecking ALL messages with shadow-based keys...\n")

all_results = []

for key in keys:
    print(f"Trying key: '{key.decode()}'")
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
                
                # Look for longer, cleaner flags
                if len(flag_content) > 8:
                    alnum_count = sum(1 for c in flag_content if c.isalnum() or c == '_')
                    alnum_ratio = alnum_count / len(flag_content) if len(flag_content) > 0 else 0
                    
                    if alnum_ratio > 0.85:  # 85% alphanumeric
                        all_results.append((key.decode(), i, flag, len(flag_content), alnum_ratio))
        except:
            pass

if all_results:
    # Sort by length, then alnum ratio
    all_results.sort(key=lambda x: (x[3], x[4]), reverse=True)
    
    print(f"\n\nFound {len(all_results)} potential flags")
    print("=" * 80)
    print("Top 20 flags (by length and quality):")
    print("=" * 80)
    
    for key, msg, flag, length, ratio in all_results[:20]:
        print(f"Key: '{key}', Message: {msg}, Length: {length}, Alnum: {ratio:.2%}")
        print(f"  {flag}\n")
    
    # Show the absolute best
    best = all_results[0]
    print("=" * 80)
    print(f"BEST FLAG: {best[2]}")
    print(f"Key: '{best[0]}', Message: {best[1]}, Length: {best[3]}, Alnum: {best[4]:.2%}")
    print("=" * 80)
else:
    print("\nNo flags found")

