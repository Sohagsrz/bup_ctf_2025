#!/usr/bin/env python3
"""
Analyze the exact order the user showed:
1. [K-99][0E8F] - "no shadow"
2. [K-99][42CE]
3. [K-13][4E01]
4. [K-07][31A3]
5. [K-99][0F83] - "the key is never in the lock"
6. First hex: 43537B2ff3b09cadea56c182af433478513eb16ee1d8e786b789b7

Maybe the key is "the key is never in the lock" or a variation?
Or maybe hex ID 0F83 is the key?
"""
from scapy.all import rdpcap, Raw, TCP
import urllib.parse
import re

packets = rdpcap('capture.pcap')

# Find the first hex message the user showed
first_hex_str = '43537B2ff3b09cadea56c182af433478513eb16ee1d8e786b789b7'

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
                        if decoded_msg.startswith('43537B'):
                            hex_messages.append(decoded_msg)
        except:
            pass

# Find the first hex message
first_hex = None
for h in hex_messages:
    if h.startswith(first_hex_str[:20]):
        first_hex = h
        break

if first_hex:
    msg_bytes = bytes.fromhex(first_hex)
    encrypted_part = msg_bytes[3:]
    
    print("Testing first hex message with various keys from user's message order")
    print("=" * 80)
    
    # Keys to try based on user's message order
    keys_to_try = [
        # From message 5: "the key is never in the lock"
        b'the key is never in the lock',
        b'the key is never in the lock.',
        b'key is never in the lock',
        b'never in the lock',
        b'key is never',
        
        # Hex IDs from the messages
        bytes.fromhex('0E8F'),  # First message
        bytes.fromhex('42CE'),  # Second
        bytes.fromhex('4E01'),  # Third
        bytes.fromhex('31A3'),  # Fourth
        bytes.fromhex('0F83'),  # Fifth (just before hex)
        
        # Combinations
        b'0E8F',
        b'42CE',
        b'4E01',
        b'31A3',
        b'0F83',
        
        # Other phrases
        b'no shadow',
        b'shadow',
        b'knights cloak but no shadow',
    ]
    
    print(f"\nTrying {len(keys_to_try)} keys...\n")
    
    for key in keys_to_try:
        try:
            decrypted = bytes([encrypted_part[i] ^ key[i % len(key)] for i in range(len(encrypted_part))])
            decoded = decrypted.decode('utf-8', errors='ignore')
            full_flag = 'CS{' + decoded
            
            flag_match = re.search(r'CS\{[A-Za-z0-9_]+\}', full_flag)
            if flag_match:
                flag = flag_match.group(0)
                flag_content = flag[3:-1]
                
                # Look for longer, cleaner flags
                if len(flag_content) > 10:
                    alnum_count = sum(1 for c in flag_content if c.isalnum() or c == '_')
                    if alnum_count / len(flag_content) > 0.8:  # 80% alphanumeric
                        key_str = key.hex() if len(key) <= 4 else key.decode('utf-8', errors='ignore')[:40]
                        print(f"Key: {key_str}")
                        print(f"Flag: {flag} (length: {len(flag)}, alnum: {alnum_count}/{len(flag_content)})")
                        if all(c.isalnum() or c == '_' for c in flag_content) and len(flag_content) > 12:
                            print(f"*** POTENTIAL FLAG: {flag} ***")
                            print()
        except:
            pass

