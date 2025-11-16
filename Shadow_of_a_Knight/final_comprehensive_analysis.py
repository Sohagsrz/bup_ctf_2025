#!/usr/bin/env python3
"""
Final comprehensive analysis:
- Analyze all knight messages for clues
- Try all possible hex ID matching strategies
- Find the longest flag
"""
from scapy.all import rdpcap, Raw, TCP
import urllib.parse
import re

packets = rdpcap('capture.pcap')

# Extract all messages with full details
all_messages = []

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
                        timestamp = float(packet.time)
                        
                        if decoded_msg.startswith('43537B'):
                            all_messages.append(('hex', timestamp, decoded_msg))
                        else:
                            msg_match = re.match(r'\[([^\]]+)\]\[([^\]]+)\]\[([^\]]+)\]\+(.+)', decoded_msg)
                            if msg_match:
                                timestamp_str, knight_id, hex_id, content = msg_match.groups()
                                content_decoded = urllib.parse.unquote(content.replace('+', ' '))
                                all_messages.append(('knight', timestamp, hex_id, knight_id, content_decoded))
        except:
            pass

all_messages.sort(key=lambda x: x[1])

knight_list = [m for m in all_messages if m[0] == 'knight']
hex_list = [m for m in all_messages if m[0] == 'hex']

print("=" * 80)
print("COMPREHENSIVE FLAG SEARCH")
print("=" * 80)
print(f"\nKnight messages: {len(knight_list)}")
print(f"Hex messages: {len(hex_list)}")

all_results = []

# Strategy 1: hex[i] uses hex ID from knight[i]
print("\n" + "=" * 80)
print("STRATEGY 1: hex[i] uses hex ID from knight[i]")
print("=" * 80)

for i in range(min(100, len(hex_list), len(knight_list))):
    hex_str = hex_list[i][2]
    hex_id = knight_list[i][2]
    
    try:
        msg_bytes = bytes.fromhex(hex_str)
        encrypted_part = msg_bytes[3:]
        key = bytes.fromhex(hex_id)
        
        decrypted = bytes([encrypted_part[j] ^ key[j % len(key)] for j in range(len(encrypted_part))])
        decoded = decrypted.decode('utf-8', errors='ignore')
        full_flag = 'CS{' + decoded
        
        flag_match = re.search(r'CS\{[A-Za-z0-9_]+\}', full_flag)
        if flag_match:
            flag = flag_match.group(0)
            flag_content = flag[3:-1]
            if len(flag_content) > 10:
                alnum = sum(1 for c in flag_content if c.isalnum() or c == '_')
                if alnum / len(flag_content) > 0.9:
                    all_results.append(('strategy1', hex_id, i+1, flag, len(flag_content)))
    except:
        pass

# Strategy 2: hex message uses hex ID from immediately preceding knight message
print("\n" + "=" * 80)
print("STRATEGY 2: hex message uses hex ID from previous knight message")
print("=" * 80)

for hex_msg in hex_list[:100]:
    hex_time, hex_str = hex_msg[1:]
    
    # Find previous knight
    prev_knight = None
    for knight_msg in reversed(knight_list):
        if knight_msg[1] < hex_time:
            prev_knight = knight_msg
            break
    
    if prev_knight:
        hex_id = prev_knight[2]
        try:
            msg_bytes = bytes.fromhex(hex_str)
            encrypted_part = msg_bytes[3:]
            key = bytes.fromhex(hex_id)
            
            decrypted = bytes([encrypted_part[j] ^ key[j % len(key)] for j in range(len(encrypted_part))])
            decoded = decrypted.decode('utf-8', errors='ignore')
            full_flag = 'CS{' + decoded
            
            flag_match = re.search(r'CS\{[A-Za-z0-9_]+\}', full_flag)
            if flag_match:
                flag = flag_match.group(0)
                flag_content = flag[3:-1]
                if len(flag_content) > 10:
                    alnum = sum(1 for c in flag_content if c.isalnum() or c == '_')
                    if alnum / len(flag_content) > 0.9:
                        idx = hex_list.index(hex_msg) + 1
                        all_results.append(('strategy2', hex_id, idx, flag, len(flag_content)))
        except:
            pass

# Strategy 3: Try all hex IDs on all messages (already done, but include best results)
print("\n" + "=" * 80)
print("STRATEGY 3: Best results from trying all hex IDs")
print("=" * 80)

# We know these work:
all_results.append(('all_hex_ids', '1062', 171, 'CS{SIwDA2a1s}', 9))
all_results.append(('all_hex_ids', '24AC', 271, 'CS{s1Is00Lww}', 9))
all_results.append(('no_shadow', 'N/A', 487, 'CS{K6oHe_}', 7))

# Print results
if all_results:
    all_results.sort(key=lambda x: x[4], reverse=True)
    print(f"\n\nFound {len(all_results)} potential flags")
    print("\nAll results (sorted by length):")
    print("-" * 80)
    
    seen = set()
    for strategy, hex_id, msg, flag, length in all_results:
        if flag not in seen:
            seen.add(flag)
            print(f"Strategy: {strategy}, Hex ID: {hex_id}, Message: {msg}, Length: {length}")
            print(f"  {flag}\n")
    
    longest = all_results[0]
    print("=" * 80)
    print(f"LONGEST FLAG: {longest[3]}")
    print(f"Strategy: {longest[0]}, Hex ID: {longest[1]}, Message: {longest[2]}, Length: {longest[4]}")
else:
    print("\nNo flags found")

