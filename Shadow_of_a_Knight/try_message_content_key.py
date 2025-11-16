#!/usr/bin/env python3
from scapy.all import rdpcap, Raw, TCP
import urllib.parse
import re

packets = rdpcap('capture.pcap')

# Extract knight messages and their content
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
                            # Extract content from knight message
                            content_match = re.match(r'\[[^\]]+\]\[[^\]]+\]\[[^\]]+\]\+(.+)', decoded_msg)
                            if content_match:
                                content = content_match.group(1)
                                # Look for potential keys in content
                                # Common words that might be keys
                                words = re.findall(r'\b[a-zA-Z]{4,}\b', content)
                                knight_messages.append((timestamp, words))
        except:
            pass

print(f"Found {len(knight_messages)} knight messages")
print(f"Found {len(hex_messages)} hex-encoded messages")

# Try using words from knight messages as keys
print("\nTrying words from knight messages as keys...")
all_words = set()
for _, words in knight_messages:
    all_words.update(words)

print(f"Unique words found: {len(all_words)}")
print(f"Sample words: {list(all_words)[:20]}")

# Try these words as keys
for word in list(all_words)[:50]:  # First 50 words
    if len(word) < 4:
        continue
    key = word.encode('utf-8')
    
    # Try on first hex message
    if hex_messages:
        hex_str = hex_messages[0][1]
        msg_bytes = bytes.fromhex(hex_str)
        encrypted_part = msg_bytes[3:]
        
        decrypted = bytes([encrypted_part[i] ^ key[i % len(key)] for i in range(len(encrypted_part))])
        try:
            decoded = decrypted.decode('utf-8', errors='ignore')
            full_flag = 'CS{' + decoded
            if re.match(r'CS\{[^}]+\}', full_flag):
                flag_match = re.search(r'CS\{[^}]+\}', full_flag)
                flag = flag_match.group(0)
                flag_content = flag[3:-1]
                # Check if it's a clean flag
                if all(c.isalnum() or c == '_' for c in flag_content) and len(flag_content) > 5:
                    print(f"\nKEY FOUND: {word}")
                    print(f"FLAG: {flag}")
                    break
        except:
            pass

# Also try common phrases
print("\nTrying common phrases as keys...")
phrases = [b'shadow', b'knight', b'shadow of a knight', b'traitor', b'sigil', b'aqueduct', b'lantern', b'battlements']
for phrase in phrases:
    key = phrase
    if hex_messages:
        hex_str = hex_messages[0][1]
        msg_bytes = bytes.fromhex(hex_str)
        encrypted_part = msg_bytes[3:]
        
        decrypted = bytes([encrypted_part[i] ^ key[i % len(key)] for i in range(len(encrypted_part))])
        try:
            decoded = decrypted.decode('utf-8', errors='ignore')
            full_flag = 'CS{' + decoded
            if re.match(r'CS\{[^}]+\}', full_flag):
                flag_match = re.search(r'CS\{[^}]+\}', full_flag)
                flag = flag_match.group(0)
                flag_content = flag[3:-1]
                if all(c.isalnum() or c == '_' for c in flag_content) and len(flag_content) > 5:
                    print(f"\nKEY FOUND: {phrase.decode()}")
                    print(f"FLAG: {flag}")
                    break
        except:
            pass

