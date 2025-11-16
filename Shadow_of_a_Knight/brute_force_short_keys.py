#!/usr/bin/env python3
from scapy.all import rdpcap, Raw, TCP
import urllib.parse
import re
import string
import itertools

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

if hex_str:
    msg_bytes = bytes.fromhex(hex_str)
    encrypted_part = msg_bytes[3:]
    
    print(f"Encrypted part length: {len(encrypted_part)} bytes")
    print(f"Trying short ASCII keys (3-8 chars)...")
    
    # Try all lowercase, uppercase, and alphanumeric combinations
    # This will take a while, so let's be smart about it
    # Try common words first
    common_words = [
        'shadow', 'knight', 'flag', 'secret', 'key', 'cipher',
        'knightsquad', 'noman', 'prodhan', 'agent', 'k99', 'k13',
        'k07', 'k21', 'k42', 'cs', 'ctf', 'challenge'
    ]
    
    for word in common_words:
        key = word.encode('utf-8')
        decrypted = bytes([encrypted_part[i] ^ key[i % len(key)] for i in range(len(encrypted_part))])
        try:
            decoded = decrypted.decode('utf-8', errors='ignore')
            full_flag = 'CS{' + decoded
            if re.match(r'CS\{[^}]+\}', full_flag):
                flag_match = re.search(r'CS\{[^}]+\}', full_flag)
                flag = flag_match.group(0)
                flag_content = flag[3:-1]
                if all(c.isalnum() or c == '_' for c in flag_content) and len(flag_content) > 5:
                    print(f"\n*** KEY FOUND: {word} ***")
                    print(f"*** FLAG: {flag} ***")
                    exit(0)
        except:
            pass
    
    # Try all 3-char lowercase combinations (this is manageable)
    print("\nTrying 3-character lowercase keys...")
    count = 0
    for key_chars in itertools.product(string.ascii_lowercase, repeat=3):
        key = ''.join(key_chars).encode('utf-8')
        decrypted = bytes([encrypted_part[i] ^ key[i % len(key)] for i in range(len(encrypted_part))])
        try:
            decoded = decrypted.decode('utf-8', errors='ignore')
            full_flag = 'CS{' + decoded
            if re.match(r'CS\{[^}]+\}', full_flag):
                flag_match = re.search(r'CS\{[^}]+\}', full_flag)
                flag = flag_match.group(0)
                flag_content = flag[3:-1]
                if all(c.isalnum() or c == '_' for c in flag_content) and len(flag_content) > 5:
                    print(f"\n*** KEY FOUND: {key.decode()} ***")
                    print(f"*** FLAG: {flag} ***")
                    exit(0)
        except:
            pass
        count += 1
        if count % 10000 == 0:
            print(f"  Tried {count} keys...")

print("\nNo flag found with short keys. The key might be longer or use a different encryption method.")

