#!/usr/bin/env python3
from scapy.all import rdpcap, DNS, Raw, TCP
import urllib.parse
import re
from collections import defaultdict

packets = rdpcap('capture.pcap')

print("=" * 80)
print("ANALYZING KNIGHT MESSAGES")
print("=" * 80)

messages = []
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
                        
                        # Skip hex-encoded messages (starting with 43537B)
                        if not decoded_msg.startswith('43537B'):
                            messages.append(decoded_msg)
        except:
            pass

print(f"Found {len(messages)} regular messages\n")

# Extract message IDs and content
message_data = []
for msg in messages:
    # Format: [timestamp][Knight-ID][Hex-ID]+message
    match = re.match(r'\[([^\]]+)\]\[([^\]]+)\]\[([^\]]+)\]\+(.+)', msg)
    if match:
        timestamp, knight_id, hex_id, content = match.groups()
        message_data.append({
            'timestamp': timestamp,
            'knight_id': knight_id,
            'hex_id': hex_id,
            'content': content
        })
        print(f"[{knight_id}][{hex_id}] {content[:80]}...")

print("\n" + "=" * 80)
print("LOOKING FOR PATTERNS IN HEX IDs")
print("=" * 80)

hex_ids = [m['hex_id'] for m in message_data]
print(f"Unique hex IDs: {len(set(hex_ids))}")
print(f"Total messages: {len(hex_ids)}")

# Group by knight
by_knight = defaultdict(list)
for m in message_data:
    by_knight[m['knight_id']].append(m)

print("\nMessages by knight:")
for knight, msgs in sorted(by_knight.items()):
    print(f"  {knight}: {len(msgs)} messages")

# Check if hex IDs form a pattern
print("\n" + "=" * 80)
print("EXTRACTING HEX IDS IN ORDER")
print("=" * 80)

# Sort by timestamp
sorted_messages = sorted(message_data, key=lambda x: x['timestamp'])
hex_id_sequence = [m['hex_id'] for m in sorted_messages]

print("First 20 hex IDs:")
for i, hex_id in enumerate(hex_id_sequence[:20], 1):
    print(f"{i}. {hex_id}")

# Try to decode hex IDs as ASCII
print("\n" + "=" * 80)
print("TRYING TO DECODE HEX IDs AS ASCII")
print("=" * 80)

decoded_hex_ids = []
for hex_id in hex_id_sequence:
    try:
        decoded = bytes.fromhex(hex_id).decode('utf-8', errors='ignore')
        if decoded.isprintable():
            decoded_hex_ids.append(decoded)
            print(f"{hex_id} -> {decoded}")
    except:
        pass

# Combine decoded hex IDs
if decoded_hex_ids:
    combined = ''.join(decoded_hex_ids)
    print(f"\nCombined: {combined[:200]}...")
    
    # Look for flag
    flag_match = re.search(r'CS\{[^}]+\}', combined)
    if flag_match:
        print(f"\nFLAG FOUND: {flag_match.group(0)}")

