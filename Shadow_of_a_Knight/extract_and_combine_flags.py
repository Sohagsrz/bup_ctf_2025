#!/usr/bin/env python3
"""
Extract flag parts from each message and try combining them
Maybe each message contributes part of the flag
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

# Try different keys and extract flag parts
keys = [b'no shadow', b'shadow', b'KnightAgent']

for key in keys:
    print(f"\n{'='*80}")
    print(f"Key: '{key.decode()}'")
    print(f"{'='*80}\n")
    
    flag_parts = []
    
    for i, hex_str in enumerate(hex_messages, 1):
        try:
            msg_bytes = bytes.fromhex(hex_str)
            encrypted_part = msg_bytes[3:]
            decrypted = bytes([encrypted_part[j] ^ key[j % len(key)] for j in range(len(encrypted_part))])
            decoded = decrypted.decode('utf-8', errors='ignore')
            full_flag = 'CS{' + decoded
            
            # Extract flag content
            flag_match = re.search(r'CS\{([A-Za-z0-9_]+)\}', full_flag)
            if flag_match:
                flag_content = flag_match.group(1)
                if len(flag_content) > 3:
                    flag_parts.append(flag_content)
        except:
            pass
    
    if flag_parts:
        print(f"Extracted {len(flag_parts)} flag parts")
        
        # Try combining all flag parts
        combined = ''.join(flag_parts)
        if len(combined) > 15:
            print(f"Combined length: {len(combined)}")
            print(f"Combined: {combined[:100]}...")
            
            # Look for a complete flag in the combined
            flag_match = re.search(r'CS\{[A-Za-z0-9_]+\}', 'CS{' + combined)
            if flag_match:
                flag = flag_match.group(0)
                if len(flag) > 15:
                    print(f"\n*** Combined flag: {flag} ***")
        
        # Also try: maybe only certain messages contain the flag
        # Filter to only alphanumeric parts
        clean_parts = [p for p in flag_parts if all(c.isalnum() or c == '_' for c in p)]
        if clean_parts:
            combined_clean = ''.join(clean_parts)
            if len(combined_clean) > 15 and all(c.isalnum() or c == '_' for c in combined_clean):
                flag = 'CS{' + combined_clean + '}'
                print(f"\n*** Clean combined flag: {flag} ***")
                print(f"Length: {len(flag)}")

