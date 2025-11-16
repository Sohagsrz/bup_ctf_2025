#!/usr/bin/env python3
"""
Comprehensive plan to find the flag:
1. Match hex-encoded messages with knight messages by timestamp
2. Try hex IDs as keys (both as hex bytes and ASCII)
3. Try combining messages
4. Try different key derivations
5. Check for patterns in message ordering
"""
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
                                all_messages.append(('knight', timestamp, hex_id, decoded_msg))
        except:
            pass

# Sort by timestamp
all_messages.sort(key=lambda x: x[1])

print(f"Total messages: {len(all_messages)}")
print(f"Knight messages: {sum(1 for m in all_messages if m[0] == 'knight')}")
print(f"Hex messages: {sum(1 for m in all_messages if m[0] == 'hex')}")

# Strategy 1: Match each hex message with the immediately preceding knight message's hex ID
print("\n" + "=" * 80)
print("STRATEGY 1: Using previous knight message hex ID as key")
print("=" * 80)

for i, msg in enumerate(all_messages):
    if msg[0] == 'hex':
        hex_str = msg[2]
        # Find previous knight message
        prev_hex_id = None
        for j in range(i-1, -1, -1):
            if all_messages[j][0] == 'knight':
                prev_hex_id = all_messages[j][2]
                break
        
        if prev_hex_id:
            try:
                # Try as hex bytes
                key_bytes = bytes.fromhex(prev_hex_id)
                msg_bytes = bytes.fromhex(hex_str)
                encrypted_part = msg_bytes[3:]
                
                decrypted = bytes([encrypted_part[j] ^ key_bytes[j % len(key_bytes)] for j in range(len(encrypted_part))])
                decoded = decrypted.decode('utf-8', errors='ignore')
                full_flag = 'CS{' + decoded
                
                if re.match(r'CS\{[^}]+\}', full_flag):
                    flag_match = re.search(r'CS\{[^}]+\}', full_flag)
                    flag = flag_match.group(0)
                    flag_content = flag[3:-1]
                    if all(c.isalnum() or c == '_' for c in flag_content) and len(flag_content) > 8:
                        print(f"\nMessage {i+1}: FLAG FOUND: {flag}")
                        print(f"Hex ID used: {prev_hex_id}")
                        break
            except:
                pass

# Strategy 2: Try combining all hex messages and decrypting
print("\n" + "=" * 80)
print("STRATEGY 2: Combining all hex messages")
print("=" * 80)

hex_messages = [m[2] for m in all_messages if m[0] == 'hex']
all_hex = ''.join(hex_messages)
all_bytes = bytes.fromhex(all_hex)

# Try common keys on combined
keys = [b'shadow', b'no shadow', b'knightsquad', b'KnightAgent']
for key in keys:
    decrypted = bytes([all_bytes[i] ^ key[i % len(key)] for i in range(min(500, len(all_bytes)))])
    try:
        decoded = decrypted.decode('utf-8', errors='ignore')
        if 'CS{' in decoded:
            flag_match = re.search(r'CS\{[A-Za-z0-9_]+\}', decoded)
            if flag_match:
                flag = flag_match.group(0)
                if len(flag) > 15:  # Longer flag
                    print(f"\nKey '{key.decode()}': {flag}")
    except:
        pass

