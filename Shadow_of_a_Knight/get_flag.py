#!/usr/bin/env python3
"""
Get the flag by decrypting all hex messages
"""
import os
import sys
import re

try:
    from scapy.all import rdpcap, Raw, TCP
    import urllib.parse
    HAS_SCAPY = True
except:
    HAS_SCAPY = False
    print("Warning: scapy not available, will try to process provided hex messages")

def process_hex_messages(hex_messages, hex_ids):
    """Process hex messages with all hex IDs and find the best flag"""
    print(f"Processing {len(hex_messages)} hex messages with {len(hex_ids)} hex IDs...\n")
    
    best_result = None
    best_score = 0
    all_results = []
    
    for hex_id in hex_ids:
        try:
            key = bytes.fromhex(hex_id)
            combined_bytes = b''
            
            for hex_str in hex_messages:
                # Remove 43537B prefix (CS{)
                hex_part = hex_str[6:] if hex_str.startswith('43537B') else hex_str
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
    
    return all_results, best_result

# Try to load from pcap file
hex_messages = []
hex_ids = []

if HAS_SCAPY:
    pcap_file = None
    for f in ['capture.pcap', '../capture.pcap', '../../capture.pcap', './Shadow_of_a_Knight/capture.pcap']:
        if os.path.exists(f):
            pcap_file = f
            break
    
    if pcap_file:
        print(f"Loading from pcap file: {pcap_file}")
        packets = rdpcap(pcap_file)
        
        # Get all hex messages
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
        
        # Get all hex IDs
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

if not hex_messages:
    print("ERROR: No hex messages found!")
    print("Please ensure capture.pcap is in the current directory")
    print("Or provide hex messages directly")
    sys.exit(1)

hex_ids = sorted(set(hex_ids)) if hex_ids else ['0E8F', '42CE', '4E01', '31A3', '0F83', '1062', '24AC', '28CF', '023A']

print(f"Found {len(hex_messages)} hex messages")
print(f"Using {len(hex_ids)} hex IDs to try")

# Process and find flag
all_results, best_result = process_hex_messages(hex_messages, hex_ids)

# Show top results
print("=" * 80)
print("TOP 5 RESULTS:")
print("=" * 80)
for i, (hex_id, text, score, printable, alpha) in enumerate(all_results[:5], 1):
    print(f"\n{i}. Hex ID {hex_id}: Score {score:.4f}")
    if 'CS{' in text:
        idx = text.index('CS{')
        flag_part = text[idx:min(idx+200, len(text))]
        print(f"   Flag: {flag_part}...")

if best_result:
    hex_id, text, score, printable, alpha = best_result
    print("\n" + "=" * 80)
    print("BEST RESULT - FLAG:")
    print("=" * 80)
    print(f"Hex ID: {hex_id}")
    print(f"Score: {score:.4f}")
    print(f"Length: {len(text)}")
    
    if 'CS{' in text:
        idx = text.index('CS{')
        print(f"\nFlag starts at position {idx}")
        print("-" * 80)
        
        # Extract complete flag
        remaining = text[idx+3:]
        if '}' in remaining:
            end_idx = remaining.index('}')
            flag = 'CS{' + remaining[:end_idx] + '}'
        else:
            # Look for pattern
            flag_match = re.search(r'CS\{[A-Za-z0-9_]{20,}', text[idx:])
            if flag_match:
                flag = flag_match.group(0) + '}'
            else:
                flag = 'CS{' + remaining[:200] + '}'
        
        print(f"\n{'='*80}")
        print(f"FLAG: {flag}")
        print(f"{'='*80}")
        print(f"\nFull text (first 500 chars):")
        print(text[idx:idx+500])

