#!/usr/bin/env python3
"""
Find a clean, long flag by extracting only alphanumeric characters
Try with different keys
"""
from scapy.all import rdpcap, Raw, TCP
import urllib.parse
import re

packets = rdpcap('capture.pcap')

hex_messages = []
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
                        if decoded_msg.startswith('43537B'):
                            hex_messages.append(decoded_msg)
                        else:
                            msg_match = re.match(r'\[[^\]]+\]\[[^\]]+\]\[([^\]]+)\]', decoded_msg)
                            if msg_match:
                                hex_id = msg_match.group(1)
                                if hex_id not in hex_ids:
                                    hex_ids.append(hex_id)
        except:
            pass

hex_ids = sorted(set(hex_ids))

print(f"Hex messages: {len(hex_messages)}")
print(f"Hex IDs: {len(hex_ids)}")

# Try with "no shadow" key
print("\n" + "=" * 80)
print("WITH 'no shadow' KEY - Extract clean alphanumeric only")
print("=" * 80)

key = b'no shadow'
clean_chars = []

for hex_str in hex_messages:
    msg_bytes = bytes.fromhex(hex_str)
    encrypted_part = msg_bytes[3:]
    decrypted = bytes([encrypted_part[i] ^ key[i % len(key)] for i in range(len(encrypted_part))])
    decoded = decrypted.decode('utf-8', errors='ignore')
    
    # Extract ONLY alphanumeric and underscore
    for c in decoded:
        if c.isalnum() or c == '_':
            clean_chars.append(c)

combined_clean = ''.join(clean_chars)
print(f"Combined clean length: {len(combined_clean)}")
print(f"First 300 chars: {combined_clean[:300]}")

# Look for flag pattern
if 'CS{' in combined_clean:
    idx = combined_clean.index('CS{')
    potential = combined_clean[idx:idx+200]
    flag_match = re.search(r'CS\{[A-Za-z0-9_]+\}', potential)
    if flag_match:
        print(f"\n*** FLAG FOUND: {flag_match.group(0)} ***")
else:
    # Maybe the flag starts somewhere in the string
    # Look for long sequences of alphanumeric
    for start in range(min(50, len(combined_clean))):
        test = combined_clean[start:start+100]
        if len(test) > 20 and all(c.isalnum() or c == '_' for c in test):
            flag = 'CS{' + test + '}'
            print(f"\nPotential flag (starting at {start}): {flag[:80]}...")
            break

# Try with hex IDs
print("\n" + "=" * 80)
print("TRYING HEX IDs AS KEYS - Extract clean alphanumeric")
print("=" * 80)

for hex_id in hex_ids[:20]:  # First 20
    try:
        key = bytes.fromhex(hex_id)
        clean_chars = []
        
        for hex_str in hex_messages:
            msg_bytes = bytes.fromhex(hex_str)
            encrypted_part = msg_bytes[3:]
            decrypted = bytes([encrypted_part[j] ^ key[j % len(key)] for j in range(len(encrypted_part))])
            decoded = decrypted.decode('utf-8', errors='ignore')
            
            for c in decoded:
                if c.isalnum() or c == '_':
                    clean_chars.append(c)
        
        combined = ''.join(clean_chars)
        if len(combined) > 30:
            # Look for flag pattern
            if 'CS{' in combined:
                idx = combined.index('CS{')
                potential = combined[idx:idx+100]
                flag_match = re.search(r'CS\{[A-Za-z0-9_]+\}', potential)
                if flag_match:
                    flag = flag_match.group(0)
                    if len(flag) > 20:
                        print(f"\nHex ID {hex_id}: {flag}")
                        print(f"  Length: {len(flag)}")
            else:
                # Check if there's a long clean sequence
                for start in range(min(20, len(combined))):
                    test = combined[start:start+50]
                    if len(test) > 20 and all(c.isalnum() or c == '_' for c in test):
                        flag = 'CS{' + test + '}'
                        if len(flag) > 25:
                            print(f"\nHex ID {hex_id}: {flag}")
                            break
    except:
        pass

