#!/usr/bin/env python3
"""
Final flag extractor: Decrypt all hex messages and combine to form the flag
Based on hint: 43537B = CS{, 7D = }, decrypt all and combine
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
print("Looking for readable flag...")
print("=" * 80)

best_result = None
best_score = 0

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
            
            score = (printable / len(combined_text)) * 0.4 + (alpha / len(combined_text)) * 0.4 + (spaces / len(combined_text)) * 0.2
            
            if score > best_score:
                best_score = score
                best_result = (hex_id, combined_text, score, printable, alpha)
            
            # Show promising results
            if score > 0.6 and 'CS{' in combined_text:
                idx = combined_text.index('CS{')
                flag_part = combined_text[idx:idx+200]
                print(f"\nHex ID {hex_id}:")
                print(f"  Score: {score:.3f} (printable: {printable/len(combined_text):.2%}, alpha: {alpha/len(combined_text):.2%})")
                print(f"  Flag starts at: {idx}")
                print(f"  Content: {flag_part}")
                
                # Try to extract complete flag
                flag_match = re.search(r'CS\{[^}]+\}', combined_text[idx:])
                if flag_match:
                    flag = flag_match.group(0)
                    if len(flag) > 30:
                        print(f"  *** EXTRACTED FLAG: {flag[:100]}... ***")
    except Exception as e:
        pass

if best_result:
    hex_id, text, score, printable, alpha = best_result
    print("\n" + "=" * 80)
    print(f"BEST RESULT:")
    print(f"Hex ID: {hex_id}")
    print(f"Score: {score:.3f}")
    print(f"Length: {len(text)}")
    if 'CS{' in text:
        idx = text.index('CS{')
        print(f"\nFlag starts at position {idx}:")
        print(text[idx:idx+300])
        
        # Extract flag
        flag_match = re.search(r'CS\{[^}]+\}', text[idx:])
        if flag_match:
            flag = flag_match.group(0)
            print(f"\n*** COMPLETE FLAG: {flag} ***")
        else:
            # Maybe flag continues to end
            potential_flag = 'CS{' + text[idx+3:]
            print(f"\n*** POTENTIAL FLAG (to end): {potential_flag[:200]}... ***")

