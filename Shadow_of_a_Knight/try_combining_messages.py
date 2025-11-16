#!/usr/bin/env python3
"""
Maybe the flag is split across multiple messages and needs to be combined
"""
from scapy.all import rdpcap, Raw, TCP
import urllib.parse
import re

packets = rdpcap('capture.pcap')

# Get all hex messages in order
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

print(f"Found {len(hex_messages)} hex-encoded messages")

# Strategy: Decrypt each message with "no shadow" key and combine
print("\n" + "=" * 80)
print("Decrypting all messages with 'no shadow' key and combining")
print("=" * 80)

key = b'no shadow'
decrypted_parts = []

for hex_str in hex_messages:
    msg_bytes = bytes.fromhex(hex_str)
    encrypted_part = msg_bytes[3:]
    decrypted = bytes([encrypted_part[i] ^ key[i % len(key)] for i in range(len(encrypted_part))])
    decrypted_parts.append(decrypted)

# Combine all decrypted parts
combined = b''.join(decrypted_parts)
try:
    combined_text = combined.decode('utf-8', errors='ignore')
    print(f"Combined length: {len(combined_text)}")
    
    # Look for flag pattern
    flag_match = re.search(r'CS\{[A-Za-z0-9_]+\}', combined_text)
    if flag_match:
        flag = flag_match.group(0)
        print(f"\n*** FLAG FOUND IN COMBINED: {flag} ***")
    else:
        # Show first 500 chars
        print(f"\nFirst 500 chars: {combined_text[:500]}")
        # Look for CS{ anywhere
        if 'CS{' in combined_text:
            idx = combined_text.index('CS{')
            print(f"\nFound CS{{ at position {idx}")
            print(f"Context: {combined_text[max(0, idx-20):idx+100]}")
except:
    pass

# Strategy: Try each message individually with "no shadow" and look for longest clean flag
print("\n" + "=" * 80)
print("Checking each message individually for longest clean flags")
print("=" * 80)

best_flags = []
for i, hex_str in enumerate(hex_messages, 1):
    msg_bytes = bytes.fromhex(hex_str)
    encrypted_part = msg_bytes[3:]
    decrypted = bytes([encrypted_part[j] ^ key[j % len(key)] for j in range(len(encrypted_part))])
    
    try:
        decoded = decrypted.decode('utf-8', errors='ignore')
        full_flag = 'CS{' + decoded
        
        flag_match = re.search(r'CS\{[A-Za-z0-9_]+\}', full_flag)
        if flag_match:
            flag = flag_match.group(0)
            flag_content = flag[3:-1]
            
            if all(c.isalnum() or c == '_' for c in flag_content) and len(flag_content) > 5:
                best_flags.append((i, flag, len(flag)))
    except:
        pass

if best_flags:
    best_flags.sort(key=lambda x: x[2], reverse=True)
    print(f"\nFound {len(best_flags)} clean flags, longest:")
    for msg, flag, length in best_flags[:10]:
        print(f"  Message {msg}: {flag} (length: {length})")

