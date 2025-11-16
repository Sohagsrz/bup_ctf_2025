#!/usr/bin/env python3
from scapy.all import rdpcap, Raw, TCP
import urllib.parse
import re
import hashlib

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

print(f"Encrypted part: {len(encrypted_part)} bytes")
print(f"Hex: {encrypted_part.hex()}")

# Try various key derivations from "shadow"
base = "shadow"
keys_to_try = [
    base.encode(),
    base.upper().encode(),
    base.capitalize().encode(),
    (base * 2).encode(),
    (base * 3).encode(),
    (base * 4).encode()[:24],  # Exactly 24 bytes
    hashlib.md5(base.encode()).digest()[:24],
    hashlib.sha1(base.encode()).digest()[:24],
    hashlib.sha256(base.encode()).digest()[:24],
    base.encode() + b'\x00' * (24 - len(base)),
    base.encode().ljust(24, b's'),
    base.encode().ljust(24, b'\x00'),
]

print("\nTrying shadow-based keys...")
for key in keys_to_try:
    key_str = key.hex() if len(key) > 20 else key.decode('utf-8', errors='ignore')
    decrypted = bytes([encrypted_part[i] ^ key[i % len(key)] for i in range(len(encrypted_part))])
    try:
        decoded = decrypted.decode('utf-8', errors='ignore')
        full_flag = 'CS{' + decoded
        if re.match(r'CS\{[^}]+\}', full_flag):
            flag_match = re.search(r'CS\{[^}]+\}', full_flag)
            flag = flag_match.group(0)
            flag_content = flag[3:-1]
            if all(c.isalnum() or c == '_' for c in flag_content) and len(flag_content) > 5:
                print(f"\n*** KEY: {key_str} ***")
                print(f"*** FLAG: {flag} ***")
                exit(0)
    except:
        pass

print("\nNo flag found. The key might be something else entirely.")
print("The encrypted messages are definitely there (500 messages starting with CS{),")
print("but the decryption key hasn't been found yet.")

