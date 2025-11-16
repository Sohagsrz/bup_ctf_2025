#!/usr/bin/env python3
"""
Try deriving keys from the actual knight message content
Maybe the key is a phrase or word from the message itself
"""
from scapy.all import rdpcap, Raw, TCP
import urllib.parse
import re

packets = rdpcap('capture.pcap')

# Extract knight messages with content and hex messages
knight_data = []
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
                            msg_match = re.match(r'\[[^\]]+\]\[[^\]]+\]\[([^\]]+)\]\+(.+)', decoded_msg)
                            if msg_match:
                                hex_id = msg_match.group(1)
                                content = msg_match.group(2)
                                knight_data.append((timestamp, hex_id, content))
        except:
            pass

# Sort by timestamp
knight_data.sort(key=lambda x: x[0])
hex_messages.sort(key=lambda x: x[0])

print(f"Knight messages: {len(knight_data)}")
print(f"Hex messages: {len(hex_messages)}")

# Strategy: For each hex message, find the closest knight message and try its content as key
print("\n" + "=" * 80)
print("Trying knight message content as keys")
print("=" * 80)

for hex_time, hex_str in hex_messages[:20]:  # First 20
    # Find closest knight message
    closest = min(knight_data, key=lambda x: abs(x[0] - hex_time))
    hex_id, content = closest[1], closest[2]
    
    # Extract potential keys from content
    # Try: last word, first word, key phrases
    words = re.findall(r'[a-zA-Z]+', content)
    phrases = []
    
    if 'no shadow' in content.lower():
        phrases.append('no shadow')
    if 'shadow' in content.lower():
        phrases.append('shadow')
    if 'the key is never in the lock' in content.lower():
        phrases.append('the key is never in the lock')
    
    # Also try hex ID
    keys_to_try = [hex_id.encode('utf-8'), bytes.fromhex(hex_id)] + [p.encode('utf-8') for p in phrases]
    
    if words:
        keys_to_try.append(words[-1].lower().encode('utf-8'))  # Last word
        keys_to_try.append(words[0].lower().encode('utf-8'))   # First word
    
    msg_bytes = bytes.fromhex(hex_str)
    encrypted_part = msg_bytes[3:]
    
    for key in keys_to_try:
        try:
            decrypted = bytes([encrypted_part[i] ^ key[i % len(key)] for i in range(len(encrypted_part))])
            decoded = decrypted.decode('utf-8', errors='ignore')
            full_flag = 'CS{' + decoded
            
            flag_match = re.search(r'CS\{[A-Za-z0-9_]+\}', full_flag)
            if flag_match:
                flag = flag_match.group(0)
                flag_content = flag[3:-1]
                
                if len(flag_content) > 10 and all(c.isalnum() or c == '_' for c in flag_content):
                    print(f"\nHex message at {hex_time}")
                    print(f"Closest knight: {content[:60]}...")
                    print(f"Key: {key}")
                    print(f"FLAG: {flag}")
                    break
        except:
            pass

