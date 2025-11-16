#!/usr/bin/env python3
"""
Decrypt all messages with "no shadow" key
Extract flag parts and try different ways to combine them
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

key = b'no shadow'
print(f"Decrypting {len(hex_messages)} messages with 'no shadow' key")
print("Extracting and combining flag parts...\n")

# Extract flag content from each message
flag_contents = []

for hex_str in hex_messages:
    msg_bytes = bytes.fromhex(hex_str)
    encrypted_part = msg_bytes[3:]
    decrypted = bytes([encrypted_part[i] ^ key[i % len(key)] for i in range(len(encrypted_part))])
    decoded = decrypted.decode('utf-8', errors='ignore')
    full_flag = 'CS{' + decoded
    
    # Extract just the content part (between CS{ and })
    flag_match = re.search(r'CS\{([^}]+)\}', full_flag)
    if flag_match:
        content = flag_match.group(1)
        # Extract only alphanumeric/underscore parts
        clean_content = ''.join(c for c in content if c.isalnum() or c == '_')
        if len(clean_content) > 0:
            flag_contents.append(clean_content)

print(f"Extracted {len(flag_contents)} flag content parts")

# Try combining all
combined = ''.join(flag_contents)
print(f"Combined length: {len(combined)}")
print(f"First 200 chars: {combined[:200]}")

# Look for a complete flag pattern
if len(combined) > 15:
    # Try to find CS{ pattern
    if 'CS{' in combined or combined.startswith('CS{'):
        idx = combined.find('CS{') if 'CS{' in combined else 0
        potential_flag = combined[idx:idx+100]
        flag_match = re.search(r'CS\{[A-Za-z0-9_]+\}', potential_flag)
        if flag_match:
            flag = flag_match.group(0)
            if len(flag) > 15:
                print(f"\n*** POTENTIAL FLAG IN COMBINED: {flag} ***")

# Also try: maybe only certain messages contain the flag
# Filter to messages with longer content
long_contents = [c for c in flag_contents if len(c) > 5]
if long_contents:
    combined_long = ''.join(long_contents)
    if len(combined_long) > 15 and all(c.isalnum() or c == '_' for c in combined_long):
        flag = 'CS{' + combined_long + '}'
        print(f"\n*** FLAG FROM LONG PARTS: {flag} ***")
        print(f"Length: {len(flag)}")

# Try: maybe the flag is in specific messages
# Check messages that gave us CS{K6oHe_}
print("\n" + "=" * 80)
print("Checking message 487 and nearby messages for longer flags")
print("=" * 80)

for i in range(485, min(490, len(hex_messages))):
    hex_str = hex_messages[i]
    msg_bytes = bytes.fromhex(hex_str)
    encrypted_part = msg_bytes[3:]
    decrypted = bytes([encrypted_part[j] ^ key[j % len(key)] for j in range(len(encrypted_part))])
    decoded = decrypted.decode('utf-8', errors='ignore')
    full_flag = 'CS{' + decoded
    
    print(f"\nMessage {i+1}:")
    print(f"  Full: {repr(full_flag)}")
    flag_match = re.search(r'CS\{[^}]+\}', full_flag)
    if flag_match:
        print(f"  Flag: {flag_match.group(0)}")

