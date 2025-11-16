#!/usr/bin/env python3
from scapy.all import rdpcap, Raw, TCP
import urllib.parse
import re
from collections import Counter

packets = rdpcap('capture.pcap')

# Get first hex message
hex_str = None
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
                        if decoded_msg.startswith('43537B'):
                            hex_str = decoded_msg
                            break
        except:
            pass

if not hex_str:
    print("No hex message found")
    exit(1)

msg_bytes = bytes.fromhex(hex_str)
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
                                # Extract words
                                words = re.findall(r'[a-zA-Z]+', content)
                                # Create 2-4 word phrases
                                for i in range(len(words) - 1):
                                    phrase = ' '.join(words[i:i+2]).lower()
                                    if 8 <= len(phrase) <= 30:
                                        phrases.add(phrase)
                                for i in range(len(words) - 2):
                                    phrase = ' '.join(words[i:i+3]).lower()
                                    if 8 <= len(phrase) <= 30:
                                        phrases.add(phrase)
        except:
            pass

print(f"Found {len(phrases)} unique phrases")
print("Trying phrases as keys...")

for phrase in list(phrases)[:100]:  # First 100 phrases
    key = phrase.encode('utf-8')
    decrypted = bytes([encrypted_part[i] ^ key[i % len(key)] for i in range(len(encrypted_part))])
    try:
        decoded = decrypted.decode('utf-8', errors='ignore')
        full_flag = 'CS{' + decoded
        if re.match(r'CS\{[^}]+\}', full_flag):
            flag_match = re.search(r'CS\{[^}]+\}', full_flag)
            flag = flag_match.group(0)
            flag_content = flag[3:-1]
            if all(c.isalnum() or c == '_' for c in flag_content) and len(flag_content) > 5:
                print(f"\n*** KEY FOUND: {phrase} ***")
                print(f"*** FLAG: {flag} ***")
                exit(0)
    except:
        pass

print("\nNo flag found with phrases from knight messages.")

