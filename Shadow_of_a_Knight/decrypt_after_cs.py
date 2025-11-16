#!/usr/bin/env python3
from scapy.all import rdpcap, Raw, TCP
import urllib.parse
import re

packets = rdpcap('capture.pcap')

# Get hex-encoded messages
hex_strings = []
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
                            hex_strings.append(decoded_msg)
        except:
            pass

print(f"Found {len(hex_strings)} hex-encoded messages")

# Decrypt the part after CS{ with different keys
if hex_strings:
    first_msg = bytes.fromhex(hex_strings[0])
    cs_part = first_msg[:3]  # CS{
    encrypted_part = first_msg[3:]  # The encrypted part
    
    print(f"\nFirst message:")
    print(f"  CS{{ part: {cs_part}")
    print(f"  Encrypted part: {encrypted_part.hex()}")
    print(f"  Encrypted part length: {len(encrypted_part)} bytes")
    
    # Try single-byte XOR on encrypted part
    print("\nTrying single-byte XOR on encrypted part...")
    for key in range(256):
        decrypted = bytes([b ^ key for b in encrypted_part])
        try:
            decoded = decrypted.decode('utf-8', errors='ignore')
            # Check if it looks like a flag
            if '}' in decoded and all(c.isprintable() or c in '{}_' for c in decoded):
                full_flag = cs_part.decode('utf-8') + decoded
                if re.match(r'CS\{[^}]+\}', full_flag):
                    print(f"\nKEY FOUND: 0x{key:02X} ({key})")
                    print(f"FLAG: {full_flag}")
                    break
        except:
            pass
    
    # Also try common multi-byte keys
    print("\nTrying common multi-byte keys...")
    keys = [b'shadow', b'knight', b'knightsquad', b'flag', b'secret', b'KnightAgent']
    
    for key in keys:
        decrypted = bytes([encrypted_part[i] ^ key[i % len(key)] for i in range(len(encrypted_part))])
        try:
            decoded = decrypted.decode('utf-8', errors='ignore')
            if '}' in decoded and all(c.isprintable() or c in '{}_' for c in decoded):
                full_flag = cs_part.decode('utf-8') + decoded
                if re.match(r'CS\{[^}]+\}', full_flag):
                    print(f"\nKEY FOUND: {key.decode()}")
                    print(f"FLAG: {full_flag}")
                    break
        except:
            pass

# Try all messages
print("\n" + "=" * 80)
print("TRYING ALL MESSAGES")
print("=" * 80)

for i, hex_str in enumerate(hex_strings[:100], 1):  # First 100
    msg_bytes = bytes.fromhex(hex_str)
    encrypted_part = msg_bytes[3:]
    
    # Try single-byte XOR
    for key in range(256):
        decrypted = bytes([b ^ key for b in encrypted_part])
        try:
            decoded = decrypted.decode('utf-8', errors='ignore')
            if '}' in decoded:
                full_flag = 'CS{' + decoded
                if re.match(r'CS\{[^}]+\}', full_flag):
                    flag_match = re.search(r'CS\{[^}]+\}', full_flag)
                    if flag_match:
                        print(f"\nMessage {i}, Key 0x{key:02X}: {flag_match.group(0)}")
                        # Check if it looks like a real flag (not just random chars)
                        flag_content = flag_match.group(0)[3:-1]
                        if len(flag_content) > 5 and any(c.isalnum() for c in flag_content):
                            print(f"POTENTIAL FLAG FOUND!")
                            break
        except:
            pass
    else:
        continue
    break

