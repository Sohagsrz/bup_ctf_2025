#!/usr/bin/env python3
"""
Try deriving keys from knight message content in different ways
"""
from scapy.all import rdpcap, Raw, TCP
import urllib.parse
import re
import hashlib

packets = rdpcap('capture.pcap')

# Get first hex message
first_hex = '43537B2ff3b09cadea56c182af433478513eb16ee1d8e786b789b7'
msg_bytes = bytes.fromhex(first_hex)
encrypted_part = msg_bytes[3:]

# Extract phrases from knight messages
phrases = set()
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
                        if not decoded_msg.startswith('43537B'):
                            content_match = re.match(r'\[[^\]]+\]\[[^\]]+\]\[[^\]]+\]\+(.+)', decoded_msg)
                            if content_match:
                                content = content_match.group(1)
                                # Extract phrases
                                if 'no shadow' in content.lower():
                                    phrases.add('no shadow')
                                if 'the key is never in the lock' in content.lower():
                                    phrases.add('the key is never in the lock')
                                if 'shadow' in content.lower():
                                    phrases.add('shadow')
        except:
            pass

print(f"Found {len(phrases)} unique phrases")
print("Trying phrases and their variations as keys...\n")

keys_to_try = []
for phrase in phrases:
    keys_to_try.append(phrase.encode('utf-8'))
    keys_to_try.append(phrase.lower().encode('utf-8'))
    keys_to_try.append(phrase.upper().encode('utf-8'))
    # Hash variations
    keys_to_try.append(hashlib.md5(phrase.encode()).digest()[:24])
    keys_to_try.append(hashlib.sha1(phrase.encode()).digest()[:24])

# Also try common words
common_words = ['shadow', 'knight', 'key', 'lock', 'traitor', 'cloak', 'moonlight']
for word in common_words:
    keys_to_try.append(word.encode('utf-8'))
    keys_to_try.append((word * 4).encode('utf-8')[:24])  # Repeat to 24 bytes

print(f"Trying {len(keys_to_try)} keys on first hex message...\n")

for key in keys_to_try:
    try:
        decrypted = bytes([encrypted_part[i] ^ key[i % len(key)] for i in range(len(encrypted_part))])
        decoded = decrypted.decode('utf-8', errors='ignore')
        full_flag = 'CS{' + decoded
        
        flag_match = re.search(r'CS\{[A-Za-z0-9_]+\}', full_flag)
        if flag_match:
            flag = flag_match.group(0)
            flag_content = flag[3:-1]
            
            if len(flag_content) > 12:
                alnum_count = sum(1 for c in flag_content if c.isalnum() or c == '_')
                if alnum_count / len(flag_content) > 0.9:  # 90% alphanumeric
                    key_str = key.hex() if len(key) <= 8 else key.decode('utf-8', errors='ignore')[:50]
                    print(f"Key: {key_str}")
                    print(f"Flag: {flag} (length: {len(flag)})")
                    if all(c.isalnum() or c == '_' for c in flag_content):
                        print(f"*** CLEAN FLAG: {flag} ***")
                        print()
    except:
        pass

