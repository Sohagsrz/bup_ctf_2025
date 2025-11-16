#!/usr/bin/env python3
from scapy.all import rdpcap, Raw, TCP
import urllib.parse
import re

packets = rdpcap('capture.pcap')

# Extract all messages with timestamps
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
                            msg_match = re.match(r'\[[^\]]+\]\[[^\]]+\]\[([^\]]+)\]', decoded_msg)
                            if msg_match:
                                hex_id = msg_match.group(1)
                                all_messages.append(('knight', timestamp, hex_id))
        except:
            pass

# Sort by timestamp
all_messages.sort(key=lambda x: x[1])

print(f"Total messages: {len(all_messages)}")

# For each hex message, find the previous knight message's hex ID
print("\nTrying previous knight hex ID as key for each hex message...")

for i, (msg_type, timestamp, data) in enumerate(all_messages):
    if msg_type == 'hex':
        # Find the most recent knight message before this
        prev_hex_id = None
        for j in range(i-1, -1, -1):
            if all_messages[j][0] == 'knight':
                prev_hex_id = all_messages[j][2]
                break
        
        if prev_hex_id:
            try:
                # Try hex ID as bytes
                key_bytes = bytes.fromhex(prev_hex_id)
                msg_bytes = bytes.fromhex(data)
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
                        print(f"*** Previous hex ID: {prev_hex_id} ***")
                        break
            except:
                pass
        
        # Also try hex ID as ASCII string
        if prev_hex_id:
            try:
                key = prev_hex_id.encode('utf-8')
                msg_bytes = bytes.fromhex(data)
                encrypted_part = msg_bytes[3:]
                
                decrypted = bytes([encrypted_part[j] ^ key[j % len(key)] for j in range(len(encrypted_part))])
                decoded = decrypted.decode('utf-8', errors='ignore')
                full_flag = 'CS{' + decoded
                
                if re.match(r'CS\{[^}]+\}', full_flag):
                    flag_match = re.search(r'CS\{[^}]+\}', full_flag)
                    flag = flag_match.group(0)
                    flag_content = flag[3:-1]
                    if all(c.isalnum() or c == '_' for c in flag_content) and len(flag_content) > 5:
                        print(f"\n*** Message {i+1}: FLAG FOUND (ASCII key): {flag} ***")
                        print(f"*** Previous hex ID: {prev_hex_id} ***")
                        break
            except:
                pass

print("\nDone checking all messages.")

