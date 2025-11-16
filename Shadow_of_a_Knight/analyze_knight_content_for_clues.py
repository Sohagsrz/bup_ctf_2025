#!/usr/bin/env python3
"""
Analyze knight message content to find clues about which hex ID to use
Maybe certain phrases or patterns indicate the correct hex ID
"""
from scapy.all import rdpcap, Raw, TCP
import urllib.parse
import re

packets = rdpcap('capture.pcap')

# Extract knight messages with full content
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
                            msg_match = re.match(r'\[([^\]]+)\]\[([^\]]+)\]\[([^\]]+)\]\+(.+)', decoded_msg)
                            if msg_match:
                                timestamp_str, knight_id, hex_id, content = msg_match.groups()
                                # Decode URL encoding in content
                                content_decoded = urllib.parse.unquote(content.replace('+', ' '))
                                knight_messages.append((timestamp, hex_id, knight_id, content_decoded))
        except:
            pass

knight_messages.sort(key=lambda x: x[0])
hex_messages.sort(key=lambda x: x[0])

print("=" * 80)
print("ANALYZING KNIGHT MESSAGES FOR CLUES")
print("=" * 80)

# Look for messages that mention "key", "shadow", "hex", etc.
print("\nKnight messages mentioning 'key' or 'shadow':")
print("-" * 80)

for timestamp, hex_id, knight_id, content in knight_messages:
    if 'key' in content.lower() or 'shadow' in content.lower() or 'hex' in content.lower():
        print(f"\n[K-{knight_id}] Hex ID: {hex_id}")
        print(f"Content: {content[:100]}...")
        
        # Try this hex ID on nearby hex messages
        # Find hex messages after this knight message
        for hex_time, hex_str in hex_messages:
            if hex_time > timestamp and hex_time - timestamp < 5:  # Within 5 seconds
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
                            print(f"  -> Hex message at {hex_time}: {flag}")
                except:
                    pass
                break

# Also check messages that mention specific phrases
print("\n" + "=" * 80)
print("CHECKING MESSAGES WITH SPECIFIC PHRASES")
print("=" * 80)

phrases_to_check = [
    'the key is never in the lock',
    'no shadow',
    'shadow under moonlight',
    'traitor',
    'fallback',
]

for phrase in phrases_to_check:
    print(f"\nMessages containing '{phrase}':")
    for timestamp, hex_id, knight_id, content in knight_messages:
        if phrase.lower() in content.lower():
            print(f"  [K-{knight_id}] Hex ID: {hex_id}")
            print(f"    {content[:80]}...")
            
            # Try this hex ID on first few hex messages
            for i, (hex_time, hex_str) in enumerate(hex_messages[:10], 1):
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
                            print(f"      -> Hex message {i}: {flag}")
                            break
                except:
                    pass

