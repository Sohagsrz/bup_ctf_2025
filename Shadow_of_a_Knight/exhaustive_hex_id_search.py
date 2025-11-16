#!/usr/bin/env python3
"""
Exhaustive search: Try every hex ID as key for every hex message
Look for the longest, cleanest flag
"""
from scapy.all import rdpcap, Raw, TCP
import urllib.parse
import re

packets = rdpcap('capture.pcap')

# Collect all hex IDs and hex messages
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
print("\nSearching for flags...\n")

best_flags = []

# Try each hex ID as key for each hex message
for hex_id in sorted(hex_ids):
    try:
        key_bytes = bytes.fromhex(hex_id)
        
        for i, hex_str in enumerate(hex_messages, 1):
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
                    
                    # Score: length and alphanumeric percentage
                    if len(flag_content) > 8:
                        alnum_count = sum(1 for c in flag_content if c.isalnum() or c == '_')
                        score = alnum_count / len(flag_content)
                        
                        if score > 0.85:  # 85% alphanumeric
                            best_flags.append((hex_id, i, flag, len(flag_content), score))
            except:
                pass
    except:
        pass

if best_flags:
    # Sort by length, then score
    best_flags.sort(key=lambda x: (x[3], x[4]), reverse=True)
    
    print(f"Found {len(best_flags)} potential flags\n")
    print("Top 20 flags (by length and quality):")
    print("=" * 80)
    
    for hex_id, msg, flag, length, score in best_flags[:20]:
        print(f"Hex ID: {hex_id}, Message: {msg}, Length: {length}, Score: {score:.2f}")
        print(f"  Flag: {flag}")
        print()
    
    # Show the best one
    best = best_flags[0]
    print("=" * 80)
    print(f"BEST FLAG: {best[2]}")
    print(f"Hex ID: {best[0]}, Message: {best[1]}, Length: {best[3]}, Score: {best[4]:.2f}")
else:
    print("No flags found with hex IDs as keys")

