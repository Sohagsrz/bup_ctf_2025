#!/usr/bin/env python3
"""
Decrypt all hex messages and combine them to form the complete flag
43537B = CS{ in hex, 7D = } in hex
"""
from scapy.all import rdpcap, Raw, TCP
import urllib.parse
import re

packets = rdpcap('capture.pcap')

# Get all hex messages in order
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

print(f"Found {len(hex_messages)} hex-encoded messages")

# Get all hex IDs from knight messages
hex_ids = []
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
                            msg_match = re.match(r'\[[^\]]+\]\[[^\]]+\]\[([^\]]+)\]', decoded_msg)
                            if msg_match:
                                hex_id = msg_match.group(1)
                                if hex_id not in hex_ids:
                                    hex_ids.append(hex_id)
        except:
            pass

hex_ids = sorted(set(hex_ids))
print(f"Found {len(hex_ids)} unique hex IDs")

# Try each hex ID: decrypt all messages and combine
print("\n" + "=" * 80)
print("DECRYPTING ALL MESSAGES AND COMBINING")
print("=" * 80)

for hex_id in hex_ids:
    try:
        key = bytes.fromhex(hex_id)
        combined_bytes = b''
        
        for hex_str in hex_messages:
            # Remove 43537B prefix (CS{)
            hex_part = hex_str[6:]
            msg_bytes = bytes.fromhex(hex_part)
            # Decrypt with XOR
            decrypted = bytes([msg_bytes[i] ^ key[i % len(key)] for i in range(len(msg_bytes))])
            combined_bytes += decrypted
        
        # Decode to text
        combined_text = combined_bytes.decode('utf-8', errors='ignore')
        
        # Check if it looks readable (contains CS{ and some readable text)
        if len(combined_text) > 50:
            # Count printable ASCII characters
            printable = sum(1 for c in combined_text if 32 <= ord(c) <= 126)
            if printable / len(combined_text) > 0.7:  # 70% printable
                if 'CS{' in combined_text:
                    idx = combined_text.index('CS{')
                    flag_part = combined_text[idx:idx+300]
                    print(f"\nHex ID {hex_id}:")
                    print(f"  Combined length: {len(combined_text)}")
                    print(f"  Printable ratio: {printable/len(combined_text):.2%}")
                    print(f"  Flag starts at position: {idx}")
                    print(f"  Flag content: {flag_part}")
                    
                    # Extract complete flag if possible
                    flag_match = re.search(r'CS\{[^}]+\}', combined_text[idx:])
                    if flag_match:
                        flag = flag_match.group(0)
                        if len(flag) > 20:
                            print(f"  *** EXTRACTED FLAG: {flag} ***")
                            print(f"  Flag length: {len(flag)}")
    except Exception as e:
        pass

