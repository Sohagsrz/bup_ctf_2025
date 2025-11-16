#!/usr/bin/env python3
"""
Decrypt all messages with each hex ID and combine the results
Maybe the flag is built from multiple decrypted messages
"""
from scapy.all import rdpcap, Raw, TCP
import urllib.parse
import re

packets = rdpcap('capture.pcap')

# Get all hex IDs and hex messages
hex_ids = []
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
                        else:
                            msg_match = re.match(r'\[[^\]]+\]\[[^\]]+\]\[([^\]]+)\]', decoded_msg)
                            if msg_match:
                                hex_ids.append(msg_match.group(1))
        except:
            pass

print(f"Hex IDs: {len(hex_ids)}")
print(f"Hex messages: {len(hex_messages)}")

# Try each hex ID: decrypt all messages and combine
print("\nTrying each hex ID - decrypting all messages and combining...\n")

for hex_id in sorted(set(hex_ids))[:20]:  # First 20 unique hex IDs
    try:
        key = bytes.fromhex(hex_id)
        combined_text = ""
        
        for hex_str in hex_messages:
            msg_bytes = bytes.fromhex(hex_str)
            encrypted_part = msg_bytes[3:]
            decrypted = bytes([encrypted_part[i] ^ key[i % len(key)] for i in range(len(encrypted_part))])
            try:
                decoded = decrypted.decode('utf-8', errors='ignore')
                combined_text += decoded
            except:
                pass
        
        # Look for flag in combined text
        if len(combined_text) > 100:
            flag_match = re.search(r'CS\{[A-Za-z0-9_]+\}', combined_text)
            if flag_match:
                flag = flag_match.group(0)
                flag_content = flag[3:-1]
                if len(flag_content) > 15 and all(c.isalnum() or c == '_' for c in flag_content):
                    print(f"Hex ID {hex_id}:")
                    print(f"  Combined length: {len(combined_text)}")
                    print(f"  Flag found: {flag}")
                    print(f"  Flag position: {combined_text.index('CS{')}")
                    print()
    except:
        pass

# Also try: maybe need to extract just the flag parts from each message
print("\n" + "=" * 80)
print("Extracting flag parts from each message and combining")
print("=" * 80)

for hex_id in ['1062', '24AC', '0E8F', '0F83']:  # Promising ones
    try:
        key = bytes.fromhex(hex_id)
        flag_parts = []
        
        for hex_str in hex_messages:
            msg_bytes = bytes.fromhex(hex_str)
            encrypted_part = msg_bytes[3:]
            decrypted = bytes([encrypted_part[i] ^ key[i % len(key)] for i in range(len(encrypted_part))])
            try:
                decoded = decrypted.decode('utf-8', errors='ignore')
                # Extract flag part
                if 'CS{' in decoded or decoded.startswith('CS{'):
                    flag_match = re.search(r'CS\{([A-Za-z0-9_]+)\}', 'CS{' + decoded)
                    if flag_match:
                        flag_parts.append(flag_match.group(1))
            except:
                pass
        
        if flag_parts:
            # Try combining flag parts
            combined_flag_content = ''.join(flag_parts)
            if len(combined_flag_content) > 15 and all(c.isalnum() or c == '_' for c in combined_flag_content):
                flag = 'CS{' + combined_flag_content + '}'
                print(f"Hex ID {hex_id}: Combined flag parts")
                print(f"  Flag: {flag}")
                print(f"  Length: {len(flag)}")
                print()
    except:
        pass

