#!/usr/bin/env python3
"""
Maybe the hex IDs form a sequence that needs to be used as a key
Or maybe each hex message uses the hex ID from a specific knight message
"""
from scapy.all import rdpcap, Raw, TCP
import urllib.parse
import re

packets = rdpcap('capture.pcap')

# Get all messages in order with full details
all_messages = []

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
                            all_messages.append(('hex', timestamp, decoded_msg))
                        else:
                            msg_match = re.match(r'\[[^\]]+\]\[([^\]]+)\]\s*\[([^\]]+)\]', decoded_msg)
                            if not msg_match:
                                msg_match = re.match(r'\[[^\]]+\]\[[^\]]+\]\[([^\]]+)\]', decoded_msg)
                            if msg_match:
                                if len(msg_match.groups()) == 2:
                                    knight_id, hex_id = msg_match.groups()
                                else:
                                    hex_id = msg_match.group(1)
                                    knight_id = None
                                all_messages.append(('knight', timestamp, hex_id, knight_id, decoded_msg))
        except:
            pass

all_messages.sort(key=lambda x: x[1])

print(f"Total messages: {len(all_messages)}")

# Strategy 1: Use hex ID from the knight message that appears just before each hex message
print("\n" + "=" * 80)
print("STRATEGY 1: Previous knight hex ID as key")
print("=" * 80)

for i, msg in enumerate(all_messages):
    if msg[0] == 'hex':
        hex_str = msg[2]
        # Find the most recent knight message before this
        for j in range(i-1, -1, -1):
            if all_messages[j][0] == 'knight':
                hex_id = all_messages[j][2]
                
                try:
                    msg_bytes = bytes.fromhex(hex_str)
                    encrypted_part = msg_bytes[3:]
                    
                    # Try hex ID as bytes
                    key = bytes.fromhex(hex_id)
                    decrypted = bytes([encrypted_part[k] ^ key[k % len(key)] for k in range(len(encrypted_part))])
                    decoded = decrypted.decode('utf-8', errors='ignore')
                    full_flag = 'CS{' + decoded
                    
                    flag_match = re.search(r'CS\{[A-Za-z0-9_]+\}', full_flag)
                    if flag_match:
                        flag = flag_match.group(0)
                        flag_content = flag[3:-1]
                        if len(flag_content) > 12 and all(c.isalnum() or c == '_' for c in flag_content):
                            print(f"\nMessage {i+1}: {flag}")
                            print(f"Hex ID used: {hex_id}")
                            print(f"Knight message: {all_messages[j][4][:80]}...")
                            print(f"*** POTENTIAL FLAG: {flag} ***")
                except:
                    pass
                break

# Strategy 2: Try combining hex IDs to form a longer key
print("\n" + "=" * 80)
print("STRATEGY 2: Combining hex IDs as key")
print("=" * 80)

knight_hex_ids = [m[2] for m in all_messages if m[0] == 'knight']
combined_hex_id = ''.join(knight_hex_ids[:10])  # First 10
print(f"Combined hex IDs (first 10): {combined_hex_id[:40]}...")

try:
    key = bytes.fromhex(combined_hex_id)
    # Try on first hex message
    if all_messages:
        for msg in all_messages:
            if msg[0] == 'hex':
                hex_str = msg[2]
                msg_bytes = bytes.fromhex(hex_str)
                encrypted_part = msg_bytes[3:]
                
                decrypted = bytes([encrypted_part[i] ^ key[i % len(key)] for i in range(len(encrypted_part))])
                decoded = decrypted.decode('utf-8', errors='ignore')
                full_flag = 'CS{' + decoded
                
                flag_match = re.search(r'CS\{[A-Za-z0-9_]+\}', full_flag)
                if flag_match:
                    flag = flag_match.group(0)
                    if len(flag) > 15:
                        print(f"Flag: {flag}")
                break
except:
    pass

