#!/usr/bin/env python3
"""
Decrypt all messages with all hex IDs and look for readable content
that might give clues about the correct key or flag
"""
from scapy.all import rdpcap, Raw, TCP
import urllib.parse
import re

packets = rdpcap('capture.pcap')

# Collect all hex IDs and hex messages
hex_ids = []
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
                                hex_id = msg_match.group(1)
                                if hex_id not in hex_ids:
                                    hex_ids.append(hex_id)
        except:
            pass

hex_ids = sorted(set(hex_ids))  # Remove duplicates and sort

print(f"Unique hex IDs: {len(hex_ids)}")
print(f"Hex messages: {len(hex_messages)}")

# Try each hex ID and look for readable content
print("\n" + "=" * 80)
print("DECRYPTING WITH ALL HEX IDs - LOOKING FOR READABLE CONTENT")
print("=" * 80)

readable_results = []

for hex_id in hex_ids[:20]:  # First 20 for speed
    try:
        key = bytes.fromhex(hex_id)
        
        for i, hex_str in enumerate(hex_messages[:50], 1):  # First 50 messages
            try:
                msg_bytes = bytes.fromhex(hex_str)
                encrypted_part = msg_bytes[3:]
                
                decrypted = bytes([encrypted_part[j] ^ key[j % len(key)] for j in range(len(encrypted_part))])
                decoded = decrypted.decode('utf-8', errors='ignore')
                
                # Check if it's mostly readable ASCII
                printable_count = sum(1 for c in decoded if 32 <= ord(c) <= 126)
                if len(decoded) > 0 and printable_count / len(decoded) > 0.8:
                    # Look for flag pattern
                    full_flag = 'CS{' + decoded
                    flag_match = re.search(r'CS\{[A-Za-z0-9_]+\}', full_flag)
                    if flag_match:
                        flag = flag_match.group(0)
                        flag_content = flag[3:-1]
                        
                        if len(flag_content) > 10:
                            readable_results.append((hex_id, i, flag, len(flag_content), decoded))
            except:
                pass
    except:
        pass

if readable_results:
    readable_results.sort(key=lambda x: x[3], reverse=True)
    print(f"\nFound {len(readable_results)} readable decryptions:\n")
    
    for hex_id, msg, flag, length, decoded in readable_results[:10]:
        print(f"Hex ID: {hex_id}, Message: {msg}")
        print(f"  Flag: {flag} (length: {length})")
        print(f"  Decoded: {decoded[:60]}...")
        print()

# Also try: maybe the key is a combination or sequence
print("\n" + "=" * 80)
print("TRYING HEX ID SEQUENCES")
print("=" * 80)

# Try first few hex IDs in sequence
if len(hex_ids) >= 5:
    first_5_hex_ids = hex_ids[:5]
    print(f"\nFirst 5 hex IDs: {first_5_hex_ids}")
    
    # Try combining them
    combined_hex = ''.join(first_5_hex_ids)
    try:
        key = bytes.fromhex(combined_hex)
        print(f"Combined key length: {len(key)} bytes")
        
        # Try on first hex message
        hex_str = hex_messages[0]
        msg_bytes = bytes.fromhex(hex_str)
        encrypted_part = msg_bytes[3:]
        
        decrypted = bytes([encrypted_part[i] ^ key[i % len(key)] for i in range(len(encrypted_part))])
        decoded = decrypted.decode('utf-8', errors='ignore')
        full_flag = 'CS{' + decoded
        
        flag_match = re.search(r'CS\{[A-Za-z0-9_]+\}', full_flag)
        if flag_match:
            flag = flag_match.group(0)
            if len(flag) > 15:
                print(f"  Result: {flag}")
    except:
        pass

