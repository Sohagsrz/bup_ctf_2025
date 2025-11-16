#!/usr/bin/env python3
"""
Systematic approach to find the flag:
- Match hex messages with knight messages by order
- Try hex IDs as keys in different ways
- Try message content as keys
- Check for patterns
"""
from scapy.all import rdpcap, Raw, TCP
import urllib.parse
import re

packets = rdpcap('capture.pcap')

# Extract messages in order
knight_msgs = []
hex_msgs = []

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
                            hex_msgs.append((timestamp, decoded_msg))
                        else:
                            msg_match = re.match(r'\[[^\]]+\]\[[^\]]+\]\[([^\]]+)\]\+(.+)', decoded_msg)
                            if msg_match:
                                hex_id = msg_match.group(1)
                                content = msg_match.group(2)
                                knight_msgs.append((timestamp, hex_id, content))
        except:
            pass

# Sort by timestamp
knight_msgs.sort(key=lambda x: x[0])
hex_msgs.sort(key=lambda x: x[0])

print(f"Knight messages: {len(knight_msgs)}")
print(f"Hex messages: {len(hex_msgs)}")

# Strategy: For each hex message, try the hex ID from the knight message at the same index
print("\n" + "=" * 80)
print("STRATEGY: Matching by index (same position in sequence)")
print("=" * 80)

for i in range(min(len(hex_msgs), len(knight_msgs))):
    hex_time, hex_str = hex_msgs[i]
    knight_time, hex_id, content = knight_msgs[i]
    
    try:
        msg_bytes = bytes.fromhex(hex_str)
        encrypted_part = msg_bytes[3:]
        
        # Try hex ID as bytes
        key_bytes = bytes.fromhex(hex_id)
        decrypted = bytes([encrypted_part[j] ^ key_bytes[j % len(key_bytes)] for j in range(len(encrypted_part))])
        decoded = decrypted.decode('utf-8', errors='ignore')
        full_flag = 'CS{' + decoded
        
        if re.match(r'CS\{[^}]+\}', full_flag):
            flag_match = re.search(r'CS\{[A-Za-z0-9_]+\}', full_flag)
            if flag_match:
                flag = flag_match.group(0)
                if len(flag) > 10:  # Looking for longer flags
                    print(f"\nMessage {i+1}: {flag}")
                    print(f"Hex ID: {hex_id}")
                    if all(c.isalnum() or c == '_' for c in flag[3:-1]) and len(flag) > 15:
                        print(f"*** POTENTIAL FLAG: {flag} ***")
    except:
        pass

# Strategy: Try words from knight message content as keys
print("\n" + "=" * 80)
print("STRATEGY: Using words from knight message content as keys")
print("=" * 80)

for i in range(min(10, len(hex_msgs), len(knight_msgs))):
    hex_time, hex_str = hex_msgs[i]
    knight_time, hex_id, content = knight_msgs[i]
    
    # Extract words from content
    words = re.findall(r'[a-zA-Z]{4,}', content)
    
    for word in words[:5]:  # First 5 words
        try:
            key = word.lower().encode('utf-8')
            msg_bytes = bytes.fromhex(hex_str)
            encrypted_part = msg_bytes[3:]
            
            decrypted = bytes([encrypted_part[j] ^ key[j % len(key)] for j in range(len(encrypted_part))])
            decoded = decrypted.decode('utf-8', errors='ignore')
            full_flag = 'CS{' + decoded
            
            if re.match(r'CS\{[^}]+\}', full_flag):
                flag_match = re.search(r'CS\{[A-Za-z0-9_]+\}', full_flag)
                if flag_match:
                    flag = flag_match.group(0)
                    if len(flag) > 15 and all(c.isalnum() or c == '_' for c in flag[3:-1]):
                        print(f"\nMessage {i+1}, Key '{word}': {flag}")
                        print(f"*** POTENTIAL FLAG: {flag} ***")
        except:
            pass

