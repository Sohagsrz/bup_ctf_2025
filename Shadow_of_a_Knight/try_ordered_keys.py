#!/usr/bin/env python3
from scapy.all import rdpcap, Raw, TCP
import urllib.parse
import re

packets = rdpcap('capture.pcap')

# Extract messages in order with timestamps
knight_messages = []
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
                        timestamp = float(packet.time)
                        
                        if decoded_msg.startswith('43537B'):
                            hex_messages.append((timestamp, decoded_msg))
                        else:
                            msg_match = re.match(r'\[[^\]]+\]\[[^\]]+\]\[([^\]]+)\]', decoded_msg)
                            if msg_match:
                                hex_id = msg_match.group(1)
                                knight_messages.append((timestamp, hex_id))
        except:
            pass

# Sort by timestamp
knight_messages.sort(key=lambda x: x[0])
hex_messages.sort(key=lambda x: x[0])

print(f"Found {len(knight_messages)} knight messages")
print(f"Found {len(hex_messages)} hex-encoded messages")

# Try matching hex messages with knight messages by order
# The user showed them interleaved, so let's try that
print("\nTrying hex IDs as keys in order...")

# Try first few
for i in range(min(20, len(hex_messages), len(knight_messages))):
    hex_time, hex_str = hex_messages[i]
    knight_time, hex_id = knight_messages[i % len(knight_messages)]
    
    try:
        # Use hex ID as bytes (hex-decoded)
        key_bytes = bytes.fromhex(hex_id)
        msg_bytes = bytes.fromhex(hex_str)
        encrypted_part = msg_bytes[3:]
        
        decrypted = bytes([encrypted_part[j] ^ key_bytes[j % len(key_bytes)] for j in range(len(encrypted_part))])
        decoded = decrypted.decode('utf-8', errors='ignore')
        full_flag = 'CS{' + decoded
        
        if re.match(r'CS\{[^}]+\}', full_flag):
            flag_match = re.search(r'CS\{[^}]+\}', full_flag)
            flag = flag_match.group(0)
            flag_content = flag[3:-1]
            if all(c.isalnum() or c == '_' for c in flag_content) and len(flag_content) > 5:
                print(f"\n*** Message {i+1}: FLAG FOUND: {flag} ***")
                print(f"*** Hex ID used: {hex_id} ***")
                break
    except Exception as e:
        pass

# Also try "shadow" variations
print("\nTrying 'shadow' variations...")
if hex_messages:
    hex_str = hex_messages[0][1]
    msg_bytes = bytes.fromhex(hex_str)
    encrypted_part = msg_bytes[3:]
    
    keys = [
        b'shadow',
        b'no shadow',
        b'shadow under moonlight',
        b'no shadow under moonlight',
        b'the traitor wears a knights cloak but no shadow',
    ]
    
    for key in keys:
        decrypted = bytes([encrypted_part[i] ^ key[i % len(key)] for i in range(len(encrypted_part))])
        try:
            decoded = decrypted.decode('utf-8', errors='ignore')
            full_flag = 'CS{' + decoded
            if re.match(r'CS\{[^}]+\}', full_flag):
                flag_match = re.search(r'CS\{[^}]+\}', full_flag)
                flag = flag_match.group(0)
                flag_content = flag[3:-1]
                if all(c.isalnum() or c == '_' for c in flag_content) and len(flag_content) > 5:
                    print(f"\n*** KEY: {key.decode()} ***")
                    print(f"*** FLAG: {flag} ***")
                    break
        except:
            pass

