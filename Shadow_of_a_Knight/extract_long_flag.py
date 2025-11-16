#!/usr/bin/env python3
"""
Extract the long flag from decrypted messages
Try different extraction methods
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

# Strategy: Decrypt with "no shadow" and extract clean alphanumeric parts
key = b'no shadow'
print("\nDecrypting all messages with 'no shadow' key...")
print("Extracting clean flag parts...\n")

all_flag_parts = []
all_decrypted = []

for hex_str in hex_messages:
    msg_bytes = bytes.fromhex(hex_str)
    encrypted_part = msg_bytes[3:]
    decrypted = bytes([encrypted_part[i] ^ key[i % len(key)] for i in range(len(encrypted_part))])
    decoded = decrypted.decode('utf-8', errors='ignore')
    all_decrypted.append(decoded)
    
    # Extract clean alphanumeric parts
    clean_part = ''.join(c for c in decoded if c.isalnum() or c == '_')
    if len(clean_part) > 0:
        all_flag_parts.append(clean_part)

# Combine all clean parts
combined_clean = ''.join(all_flag_parts)
print(f"Combined clean parts length: {len(combined_clean)}")
print(f"First 200 chars: {combined_clean[:200]}")

# Look for flag pattern in combined
if 'CS{' in combined_clean:
    idx = combined_clean.index('CS{')
    potential_flag = combined_clean[idx:idx+200]
    flag_match = re.search(r'CS\{[A-Za-z0-9_]+\}', potential_flag)
    if flag_match:
        flag = flag_match.group(0)
        print(f"\n*** FLAG FOUND: {flag} ***")
        print(f"Length: {len(flag)}")

# Also try: extract from each message individually and look for longer flags
print("\n" + "=" * 80)
print("Checking each message for longer flags")
print("=" * 80)

long_flags = []
for i, decoded in enumerate(all_decrypted, 1):
    full_text = 'CS{' + decoded
    # Look for flag pattern
    flag_match = re.search(r'CS\{[A-Za-z0-9_]+\}', full_text)
    if flag_match:
        flag = flag_match.group(0)
        flag_content = flag[3:-1]
        if len(flag_content) > 15:  # Looking for longer flags
            alnum = sum(1 for c in flag_content if c.isalnum() or c == '_')
            if alnum / len(flag_content) > 0.9:
                long_flags.append((i, flag, len(flag_content)))

if long_flags:
    long_flags.sort(key=lambda x: x[2], reverse=True)
    print(f"\nFound {len(long_flags)} flags longer than 15 characters:")
    for msg, flag, length in long_flags[:10]:
        print(f"  Message {msg}: {flag} (length: {length})")
else:
    print("\nNo individual flags longer than 15 characters found")

# Try: Maybe extract specific positions from each message
print("\n" + "=" * 80)
print("Extracting characters from specific positions")
print("=" * 80)

# Try first character from each
first_chars = []
for decoded in all_decrypted:
    for c in decoded:
        if c.isalnum() or c == '_':
            first_chars.append(c)
            break

if first_chars:
    combined_first = ''.join(first_chars)
    if len(combined_first) > 20:
        # Look for flag pattern
        if 'CS{' in combined_first:
            idx = combined_first.index('CS{')
            potential = combined_first[idx:idx+100]
            flag_match = re.search(r'CS\{[A-Za-z0-9_]+\}', potential)
            if flag_match:
                print(f"Flag from first chars: {flag_match.group(0)}")
        else:
            # Maybe the flag starts after some characters
            for start in range(min(10, len(combined_first))):
                test_str = combined_first[start:]
                if len(test_str) > 20 and all(c.isalnum() or c == '_' for c in test_str[:50]):
                    flag = 'CS{' + test_str + '}'
                    print(f"Potential flag (starting at pos {start}): {flag[:100]}...")

