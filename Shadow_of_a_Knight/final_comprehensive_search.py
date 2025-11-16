#!/usr/bin/env python3
"""
Final comprehensive search - try everything systematically
"""
from scapy.all import rdpcap, Raw, TCP
import urllib.parse
import re

packets = rdpcap('capture.pcap')

# Get all hex messages
hex_messages = []
knight_hex_ids = []

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
                        timestamp = float(packet.time)
                        
                        if decoded_msg.startswith('43537B'):
                            hex_messages.append((timestamp, decoded_msg))
                        else:
                            msg_match = re.match(r'\[[^\]]+\]\[[^\]]+\]\[([^\]]+)\]', decoded_msg)
                            if msg_match:
                                knight_hex_ids.append((timestamp, msg_match.group(1)))
        except:
            pass

hex_messages.sort(key=lambda x: x[0])
knight_hex_ids.sort(key=lambda x: x[0])

print(f"Hex messages: {len(hex_messages)}")
print(f"Knight hex IDs: {len(knight_hex_ids)}")

# Try matching each hex message with knight hex ID by index
print("\n" + "=" * 80)
print("Matching by index position")
print("=" * 80)

for i in range(min(50, len(hex_messages), len(knight_hex_ids))):
    hex_time, hex_str = hex_messages[i]
    knight_time, hex_id = knight_hex_ids[i]
    
    try:
        msg_bytes = bytes.fromhex(hex_str)
        encrypted_part = msg_bytes[3:]
        key = bytes.fromhex(hex_id)
        
        decrypted = bytes([encrypted_part[j] ^ key[j % len(key)] for j in range(len(encrypted_part))])
        decoded = decrypted.decode('utf-8', errors='ignore')
        full_flag = 'CS{' + decoded
        
        flag_match = re.search(r'CS\{[A-Za-z0-9_]+\}', full_flag)
        if flag_match:
            flag = flag_match.group(0)
            flag_content = flag[3:-1]
            if len(flag_content) > 12 and all(c.isalnum() or c == '_' for c in flag_content):
                print(f"\nMessage {i+1}: {flag}")
                print(f"Hex ID: {hex_id}")
                print(f"*** POTENTIAL FLAG: {flag} ***")
    except:
        pass

# Try: maybe the key is the hex ID repeated or padded
print("\n" + "=" * 80)
print("Trying hex ID variations (repeated, padded)")
print("=" * 80)

if hex_messages and knight_hex_ids:
    hex_str = hex_messages[0][1]
    hex_id = knight_hex_ids[0][1]
    msg_bytes = bytes.fromhex(hex_str)
    encrypted_part = msg_bytes[3:]
    
    key_base = bytes.fromhex(hex_id)
    
    # Try different key variations
    key_variations = [
        key_base,
        key_base * 12,  # Repeat to 24 bytes
        key_base + b'\x00' * (24 - len(key_base)),  # Pad with nulls
        key_base.ljust(24, b'\x00'),
    ]
    
    for key in key_variations:
        decrypted = bytes([encrypted_part[i] ^ key[i % len(key)] for i in range(len(encrypted_part))])
        decoded = decrypted.decode('utf-8', errors='ignore')
        full_flag = 'CS{' + decoded
        
        flag_match = re.search(r'CS\{[A-Za-z0-9_]+\}', full_flag)
        if flag_match:
            flag = flag_match.group(0)
            if len(flag) > 15:
                print(f"Key variation: {flag[:80]}...")

# Try: maybe need to use hex ID from a different position
print("\n" + "=" * 80)
print("Trying hex ID from offset positions")
print("=" * 80)

if hex_messages:
    hex_str = hex_messages[0][1]
    msg_bytes = bytes.fromhex(hex_str)
    encrypted_part = msg_bytes[3:]
    
    # Try hex IDs from different knight message positions
    for offset in [0, 1, 2, 3, 4, -1, -2]:
        if 0 <= offset < len(knight_hex_ids) or -len(knight_hex_ids) <= offset < 0:
            hex_id = knight_hex_ids[offset][1]
            try:
                key = bytes.fromhex(hex_id)
                decrypted = bytes([encrypted_part[i] ^ key[i % len(key)] for i in range(len(encrypted_part))])
                decoded = decrypted.decode('utf-8', errors='ignore')
                full_flag = 'CS{' + decoded
                
                flag_match = re.search(r'CS\{[A-Za-z0-9_]+\}', full_flag)
                if flag_match:
                    flag = flag_match.group(0)
                    flag_content = flag[3:-1]
                    if len(flag_content) > 12 and all(c.isalnum() or c == '_' for c in flag_content):
                        print(f"Offset {offset}, Hex ID {hex_id}: {flag}")
            except:
                pass

