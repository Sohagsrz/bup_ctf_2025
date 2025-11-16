#!/usr/bin/env python3
"""
Extract flag from hex messages - works with or without pcap file
"""
import os
import sys
from scapy.all import rdpcap, Raw, TCP
import urllib.parse
import re

# Try to find pcap file
pcap_file = None
for f in ['capture.pcap', '../capture.pcap', '../../capture.pcap']:
    if os.path.exists(f):
        pcap_file = f
        break

if not pcap_file:
    print("ERROR: capture.pcap file not found!")
    print("Please ensure capture.pcap is in the current directory or parent directories")
    sys.exit(1)

print(f"Using pcap file: {pcap_file}")
packets = rdpcap(pcap_file)

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

best_result = None
best_score = 0
all_results = []

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
        
        if len(combined_text) > 50:
            # Score based on readability
            printable = sum(1 for c in combined_text if 32 <= ord(c) <= 126)
            alpha = sum(1 for c in combined_text if c.isalpha())
            spaces = sum(1 for c in combined_text if c == ' ')
            digits = sum(1 for c in combined_text if c.isdigit())
            underscores = sum(1 for c in combined_text if c == '_')
            
            # Good flag has: letters, numbers, underscores, maybe spaces
            score = (printable / len(combined_text)) * 0.3 + \
                   (alpha / len(combined_text)) * 0.3 + \
                   (spaces / len(combined_text)) * 0.1 + \
                   ((digits + underscores) / len(combined_text)) * 0.3
            
            all_results.append((hex_id, combined_text, score, printable, alpha))
            
            if score > best_score:
                best_score = score
                best_result = (hex_id, combined_text, score, printable, alpha)
    except Exception as e:
        pass

# Sort results by score
all_results.sort(key=lambda x: x[2], reverse=True)

print(f"\nTop 5 results by readability score:\n")
for i, (hex_id, text, score, printable, alpha) in enumerate(all_results[:5], 1):
    print(f"{i}. Hex ID {hex_id}: Score {score:.4f}")
    if 'CS{' in text:
        idx = text.index('CS{')
        flag_part = text[idx:idx+150]
        print(f"   Flag content: {flag_part}...")
    print()

if best_result:
    hex_id, text, score, printable, alpha = best_result
    print("=" * 80)
    print(f"BEST RESULT:")
    print(f"Hex ID: {hex_id}")
    print(f"Score: {score:.4f}")
    print(f"Length: {len(text)}")
    print(f"Printable: {printable}/{len(text)} ({printable/len(text):.2%})")
    print(f"Alphabetic: {alpha}/{len(text)} ({alpha/len(text):.2%})")
    
    if 'CS{' in text:
        idx = text.index('CS{')
        print(f"\nFlag starts at position {idx}:")
        print("-" * 80)
        print(text[idx:idx+500])
        print("-" * 80)
        
        # Extract flag - look for CS{...} pattern
        flag_match = re.search(r'CS\{[^}]+\}', text[idx:])
        if flag_match:
            flag = flag_match.group(0)
            print(f"\n*** COMPLETE FLAG: {flag} ***")
            print(f"Flag length: {len(flag)}")
        else:
            # Maybe the flag continues to a closing brace
            remaining = text[idx+3:]
            if '}' in remaining:
                end_idx = remaining.index('}')
                flag = 'CS{' + remaining[:end_idx] + '}'
                print(f"\n*** EXTRACTED FLAG: {flag} ***")
                print(f"Flag length: {len(flag)}")
            else:
                # Take first reasonable length
                potential_flag = 'CS{' + remaining[:200]
                print(f"\n*** POTENTIAL FLAG (first 200 chars): {potential_flag}... ***")

