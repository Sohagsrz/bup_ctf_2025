#!/usr/bin/env python3
"""
Final check: Try "shadow" and "no shadow" on ALL messages
Show ALL potential flags, even if not perfectly clean
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

print(f"Total hex messages: {len(hex_messages)}")

for key_name, key in [('no shadow', b'no shadow'), ('shadow', b'shadow')]:
    print(f"\n{'='*80}")
    print(f"Key: '{key_name}'")
    print(f"{'='*80}\n")
    
    all_results = []
    
    for i, hex_str in enumerate(hex_messages, 1):
        try:
            msg_bytes = bytes.fromhex(hex_str)
            encrypted_part = msg_bytes[3:]
            decrypted = bytes([encrypted_part[j] ^ key[j % len(key)] for j in range(len(encrypted_part))])
            decoded = decrypted.decode('utf-8', errors='ignore')
            full_flag = 'CS{' + decoded
            
            # Look for any CS{...} pattern
            flag_match = re.search(r'CS\{[^}]+\}', full_flag)
            if flag_match:
                flag = flag_match.group(0)
                flag_content = flag[3:-1]
                
                if len(flag_content) > 8:
                    # Count printable characters
                    printable = sum(1 for c in flag_content if c.isprintable())
                    alnum = sum(1 for c in flag_content if c.isalnum() or c == '_')
                    
                    all_results.append((i, flag, len(flag_content), printable, alnum))
        
        except:
            pass
    
    if all_results:
        # Sort by length
        all_results.sort(key=lambda x: x[2], reverse=True)
        
        print(f"Found {len(all_results)} potential flags\n")
        print("Top 20 flags (by length):")
        print("-" * 80)
        
        for msg, flag, length, printable, alnum in all_results[:20]:
            print(f"Message {msg:3d}: {flag}")
            print(f"  Length: {length}, Printable: {printable}/{length}, Alnum: {alnum}/{length}")
            print()
    else:
        print("No flags found")

