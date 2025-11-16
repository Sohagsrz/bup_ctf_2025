#!/usr/bin/env python3
"""
Match the exact pattern the user showed:
- Knight messages with hex IDs
- Hex-encoded messages interleaved
- Try to find the relationship
"""
from scapy.all import rdpcap, Raw, TCP
import urllib.parse
import re

packets = rdpcap('capture.pcap')

# Get all messages in order
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
                                all_msgs.append(('knight', timestamp, msg_match.group(1)))
        except:
            pass

all_msgs.sort(key=lambda x: x[1])

# Find the first hex message the user showed
first_hex_str = '43537B2ff3b09cadea56c182af433478513eb16ee1d8e786b789b7'
first_hex_idx = None

for i, msg in enumerate(all_msgs):
    if msg[0] == 'hex' and msg[2].startswith(first_hex_str[:20]):
        first_hex_idx = i
        break

if first_hex_idx:
    print(f"First hex message found at index {first_hex_idx}")
    print(f"Total messages before it: {first_hex_idx}")
    
    # Count knight messages before it
    knight_before = sum(1 for i in range(first_hex_idx) if all_msgs[i][0] == 'knight')
    print(f"Knight messages before first hex: {knight_before}")
    
    # The user showed 5 knight messages before the first hex
    # So maybe hex message N uses hex ID from knight message N-5?
    # Or maybe hex message N uses hex ID from knight message at position N?
    
    print("\nTrying different matching strategies...\n")
    
    hex_msg = all_msgs[first_hex_idx]
    hex_str = hex_msg[2]
    msg_bytes = bytes.fromhex(hex_str)
    encrypted_part = msg_bytes[3:]
    
    # Try hex IDs from knight messages at different offsets
    knight_hex_ids = [m[2] for m in all_msgs[:first_hex_idx] if m[0] == 'knight']
    
    print(f"Available knight hex IDs before first hex: {len(knight_hex_ids)}")
    print(f"Last 5 hex IDs: {knight_hex_ids[-5:]}")
    
    # Try the last few hex IDs
    for offset in [-1, -2, -3, -4, -5]:
        if abs(offset) <= len(knight_hex_ids):
            hex_id = knight_hex_ids[offset]
            try:
                key = bytes.fromhex(hex_id)
                decrypted = bytes([encrypted_part[i] ^ key[i % len(key)] for i in range(len(encrypted_part))])
                decoded = decrypted.decode('utf-8', errors='ignore')
                full_flag = 'CS{' + decoded
                
                flag_match = re.search(r'CS\{[A-Za-z0-9_]+\}', full_flag)
                if flag_match:
                    flag = flag_match.group(0)
                    flag_content = flag[3:-1]
                    print(f"Offset {offset}, Hex ID {hex_id}: {flag[:60]}...")
                    if len(flag_content) > 12 and all(c.isalnum() or c == '_' for c in flag_content):
                        print(f"*** POTENTIAL FLAG: {flag} ***")
            except:
                pass

# Also try: maybe each hex message uses the hex ID from the knight message at the same index
print("\n" + "=" * 80)
print("Trying: hex message[i] uses hex ID from knight message[i]")
print("=" * 80)

knight_list = [m for m in all_msgs if m[0] == 'knight']
hex_list = [m for m in all_msgs if m[0] == 'hex']

for i in range(min(100, len(hex_list), len(knight_list))):
    hex_str = hex_list[i][2]
    hex_id = knight_list[i][2]
    
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
            if len(flag_content) > 15 and all(c.isalnum() or c == '_' for c in flag_content):
                print(f"Message {i+1}: {flag}")
                print(f"Hex ID: {hex_id}")
                print(f"*** POTENTIAL FLAG: {flag} ***")
                break
    except:
        pass

