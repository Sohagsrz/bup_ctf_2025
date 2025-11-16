#!/usr/bin/env python3
from scapy.all import rdpcap, Raw, TCP
import urllib.parse
import re
import string

packets = rdpcap('capture.pcap')

# Get all hex messages
hex_strings = []
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
                            hex_strings.append(decoded_msg)
        except:
            pass

print(f"Found {len(hex_strings)} hex-encoded messages")

# Try "shadow" as key on all messages
key = b'shadow'
print(f"\nTrying key 'shadow' on all messages...")

for i, hex_str in enumerate(hex_strings, 1):
    msg_bytes = bytes.fromhex(hex_str)
    encrypted_part = msg_bytes[3:]  # After CS{
    
    decrypted = bytes([encrypted_part[j] ^ key[j % len(key)] for j in range(len(encrypted_part))])
    try:
        decoded = decrypted.decode('utf-8', errors='ignore')
        full_flag = 'CS{' + decoded
        
        if re.match(r'CS\{[^}]+\}', full_flag):
            flag_match = re.search(r'CS\{[^}]+\}', full_flag)
            flag = flag_match.group(0)
            flag_content = flag[3:-1]
            
            # Check if it's a clean flag
            if all(c.isalnum() or c == '_' for c in flag_content) and len(flag_content) > 5:
                print(f"\n*** Message {i}: FLAG FOUND: {flag} ***")
                print(f"*** Hex: {hex_str[:60]}... ***")
                break
            # Also show any that look promising
            elif len(flag_content) > 10 and sum(1 for c in flag_content if c.isalnum() or c == '_') > len(flag_content) * 0.5:
                print(f"Message {i}: {flag[:80]}...")
    except:
        pass

# Also try "no shadow"
print("\n\nTrying key 'no shadow' on all messages...")
key = b'no shadow'

for i, hex_str in enumerate(hex_strings, 1):
    msg_bytes = bytes.fromhex(hex_str)
    encrypted_part = msg_bytes[3:]
    
    decrypted = bytes([encrypted_part[j] ^ key[j % len(key)] for j in range(len(encrypted_part))])
    try:
        decoded = decrypted.decode('utf-8', errors='ignore')
        full_flag = 'CS{' + decoded
        
        if re.match(r'CS\{[^}]+\}', full_flag):
            flag_match = re.search(r'CS\{[^}]+\}', full_flag)
            flag = flag_match.group(0)
            flag_content = flag[3:-1]
            
            if all(c.isalnum() or c == '_' for c in flag_content) and len(flag_content) > 5:
                print(f"\n*** Message {i}: FLAG FOUND: {flag} ***")
                break
            elif len(flag_content) > 10 and sum(1 for c in flag_content if c.isalnum() or c == '_') > len(flag_content) * 0.5:
                print(f"Message {i}: {flag[:80]}...")
    except:
        pass

