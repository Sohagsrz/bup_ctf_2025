#!/usr/bin/env python3
"""
Match messages in the exact order the user showed:
1. [K-99][0E8F] - "no shadow"
2. [K-99][42CE] 
3. [K-13][4E01]
4. [K-07][31A3]
5. [K-99][0F83]
6. Then first hex: 43537B2ff3b09cadea56c182af433478513eb16ee1d8e786b789b7

Maybe the hex ID from message 5 (0F83) is the key for the first hex message?
"""
from scapy.all import rdpcap, Raw, TCP
import urllib.parse
import re

packets = rdpcap('capture.pcap')

# Get messages in order
all_msgs = []
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
                            all_msgs.append(('hex', timestamp, decoded_msg))
                        else:
                            msg_match = re.match(r'\[[^\]]+\]\[[^\]]+\]\[([^\]]+)\]', decoded_msg)
                            if msg_match:
                                hex_id = msg_match.group(1)
                                all_msgs.append(('knight', timestamp, hex_id, decoded_msg))
        except:
            pass

all_msgs.sort(key=lambda x: x[1])

# Find the first hex message (the one user showed)
first_hex = None
for msg in all_msgs:
    if msg[0] == 'hex' and msg[2].startswith('43537B2ff3b09cadea56c182af433478513eb16ee1d8e786b789b7'):
        first_hex = msg
        break

if first_hex:
    hex_str = first_hex[2]
    hex_time = first_hex[1]
    
    print(f"Found first hex message at timestamp {hex_time}")
    print(f"Hex: {hex_str[:60]}...")
    
    # Find knight messages before this
    prev_knight_ids = []
    for msg in all_msgs:
        if msg[0] == 'knight' and msg[1] < hex_time:
            prev_knight_ids.append(msg[2])
    
    print(f"\nPrevious knight hex IDs: {prev_knight_ids[:10]}")
    
    # Try each previous hex ID as key
    msg_bytes = bytes.fromhex(hex_str)
    encrypted_part = msg_bytes[3:]
    
    print("\nTrying previous hex IDs as keys...")
    for hex_id in prev_knight_ids[-5:]:  # Last 5 before hex message
        try:
            # As hex bytes
            key = bytes.fromhex(hex_id)
            decrypted = bytes([encrypted_part[i] ^ key[i % len(key)] for i in range(len(encrypted_part))])
            decoded = decrypted.decode('utf-8', errors='ignore')
            full_flag = 'CS{' + decoded
            
            flag_match = re.search(r'CS\{[A-Za-z0-9_]+\}', full_flag)
            if flag_match:
                flag = flag_match.group(0)
                if len(flag) > 10:
                    print(f"Hex ID {hex_id} (bytes): {flag}")
                    if len(flag) > 15 and all(c.isalnum() or c == '_' for c in flag[3:-1]):
                        print(f"*** POTENTIAL FLAG: {flag} ***")
        except:
            pass

# Also try: maybe each hex message corresponds to a specific knight message
# Try matching by the pattern the user showed
print("\n" + "=" * 80)
print("Trying to match by the exact pattern user showed")
print("=" * 80)

# User showed: after [K-99][0F83], the first hex appears
# So maybe hex ID 0F83 is the key?
hex_id_to_try = '0F83'
print(f"\nTrying hex ID {hex_id_to_try} as key for first hex message...")

msg_bytes = bytes.fromhex(hex_str)
encrypted_part = msg_bytes[3:]

# As bytes
key = bytes.fromhex(hex_id_to_try)
decrypted = bytes([encrypted_part[i] ^ key[i % len(key)] for i in range(len(encrypted_part))])
decoded = decrypted.decode('utf-8', errors='ignore')
full_flag = 'CS{' + decoded
print(f"Result: {full_flag[:100]}...")

flag_match = re.search(r'CS\{[A-Za-z0-9_]+\}', full_flag)
if flag_match:
    flag = flag_match.group(0)
    print(f"Extracted flag: {flag}")

