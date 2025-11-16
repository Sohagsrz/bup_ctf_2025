#!/usr/bin/env python3
"""
The flag must be longer - maybe it's split across multiple messages
Try combining decrypted parts from multiple messages
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

# Strategy 1: Decrypt all with "no shadow" and extract flag parts, then combine
print("\n" + "=" * 80)
print("STRATEGY 1: Decrypt all with 'no shadow', extract flag parts, combine")
print("=" * 80)

key = b'no shadow'
flag_parts = []

for hex_str in hex_messages:
    msg_bytes = bytes.fromhex(hex_str)
    encrypted_part = msg_bytes[3:]
    decrypted = bytes([encrypted_part[i] ^ key[i % len(key)] for i in range(len(encrypted_part))])
    decoded = decrypted.decode('utf-8', errors='ignore')
    
    # Extract alphanumeric parts that might be flag content
    flag_match = re.search(r'CS\{([A-Za-z0-9_]+)\}', 'CS{' + decoded)
    if flag_match:
        content = flag_match.group(1)
        # Only keep if it's mostly alphanumeric
        if all(c.isalnum() or c == '_' for c in content) and len(content) > 3:
            flag_parts.append(content)

if flag_parts:
    print(f"Extracted {len(flag_parts)} flag parts")
    combined = ''.join(flag_parts)
    if len(combined) > 15:
        flag = 'CS{' + combined + '}'
        print(f"Combined flag: {flag}")
        print(f"Length: {len(flag)}")

# Strategy 2: Try each hex ID, decrypt all messages, extract and combine flag parts
print("\n" + "=" * 80)
print("STRATEGY 2: Try each hex ID, decrypt all, extract and combine")
print("=" * 80)

# Get all hex IDs
hex_ids = []
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
                        if not decoded_msg.startswith('43537B'):
                            msg_match = re.match(r'\[[^\]]+\]\[[^\]]+\]\[([^\]]+)\]', decoded_msg)
                            if msg_match:
                                hex_id = msg_match.group(1)
                                if hex_id not in hex_ids:
                                    hex_ids.append(hex_id)
        except:
            pass

hex_ids = sorted(set(hex_ids))
print(f"Trying {len(hex_ids)} hex IDs...\n")

for hex_id in hex_ids[:30]:  # First 30 for speed
    try:
        key = bytes.fromhex(hex_id)
        flag_parts = []
        
        for hex_str in hex_messages:
            msg_bytes = bytes.fromhex(hex_str)
            encrypted_part = msg_bytes[3:]
            decrypted = bytes([encrypted_part[j] ^ key[j % len(key)] for j in range(len(encrypted_part))])
            decoded = decrypted.decode('utf-8', errors='ignore')
            
            flag_match = re.search(r'CS\{([A-Za-z0-9_]+)\}', 'CS{' + decoded)
            if flag_match:
                content = flag_match.group(1)
                if all(c.isalnum() or c == '_' for c in content) and len(content) > 3:
                    flag_parts.append(content)
        
        if flag_parts:
            combined = ''.join(flag_parts)
            if len(combined) > 20:  # Looking for longer flags
                flag = 'CS{' + combined + '}'
                print(f"Hex ID {hex_id}: Combined flag length {len(flag)}")
                print(f"  {flag[:100]}...")
                if all(c.isalnum() or c == '_' for c in combined):
                    print(f"  *** CLEAN FLAG: {flag} ***")
    except:
        pass

# Strategy 3: Maybe each message contributes one character or a few characters
print("\n" + "=" * 80)
print("STRATEGY 3: Extract single characters from each decrypted message")
print("=" * 80)

# Try with "no shadow"
key = b'no shadow'
combined_chars = []

for hex_str in hex_messages:
    msg_bytes = bytes.fromhex(hex_str)
    encrypted_part = msg_bytes[3:]
    decrypted = bytes([encrypted_part[i] ^ key[i % len(key)] for i in range(len(encrypted_part))])
    decoded = decrypted.decode('utf-8', errors='ignore')
    
    # Extract first alphanumeric character
    for c in decoded:
        if c.isalnum() or c == '_':
            combined_chars.append(c)
            break

if combined_chars:
    combined = ''.join(combined_chars)
    if len(combined) > 20:
        flag = 'CS{' + combined + '}'
        print(f"Combined from first chars: {flag[:100]}...")
        if 'CS{' in combined or all(c.isalnum() or c == '_' for c in combined[:50]):
            print(f"Length: {len(flag)}")

