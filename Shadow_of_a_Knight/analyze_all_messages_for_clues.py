#!/usr/bin/env python3
"""
Analyze all XOR-encrypted messages and knight messages to find clues
about which hex IDs to use as keys
"""
from scapy.all import rdpcap, Raw, TCP
import urllib.parse
import re

packets = rdpcap('capture.pcap')

# Extract all messages with timestamps
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
                            # Knight message
                            msg_match = re.match(r'\[([^\]]+)\]\[([^\]]+)\]\[([^\]]+)\]\+(.+)', decoded_msg)
                            if msg_match:
                                timestamp_str, knight_id, hex_id, content = msg_match.groups()
                                all_messages.append(('knight', timestamp, hex_id, knight_id, content))
        except:
            pass

# Sort by timestamp
all_messages.sort(key=lambda x: x[1])

print("=" * 80)
print("ANALYZING MESSAGE PATTERNS FOR CLUES")
print("=" * 80)

# Separate knight and hex messages
knight_msgs = [m for m in all_messages if m[0] == 'knight']
hex_msgs = [m for m in all_messages if m[0] == 'hex']

print(f"\nTotal knight messages: {len(knight_msgs)}")
print(f"Total hex-encoded messages: {len(hex_msgs)}")

# Look for patterns in knight messages
print("\n" + "=" * 80)
print("KNIGHT MESSAGES WITH HEX IDs (first 20)")
print("=" * 80)

for i, msg in enumerate(knight_msgs[:20], 1):
    timestamp, hex_id, knight_id, content = msg[1:]
    print(f"\n{i}. [K-{knight_id}] Hex ID: {hex_id}")
    print(f"   Content: {content[:80]}...")

# Try to match hex messages with knight messages
print("\n" + "=" * 80)
print("TRYING TO MATCH HEX MESSAGES WITH PREVIOUS KNIGHT MESSAGES")
print("=" * 80)

# Strategy: For each hex message, find the immediately preceding knight message
matches_found = []

for i, hex_msg in enumerate(hex_msgs[:50], 1):  # First 50
    hex_time, hex_str = hex_msg[1:]
    
    # Find the most recent knight message before this hex message
    prev_knight = None
    for knight_msg in reversed(knight_msgs):
        if knight_msg[1] < hex_time:
            prev_knight = knight_msg
            break
    
    if prev_knight:
        timestamp, hex_id, knight_id, content = prev_knight[1:]
        
        # Try decrypting with this hex ID
        try:
            msg_bytes = bytes.fromhex(hex_str)
            encrypted_part = msg_bytes[3:]
            key = bytes.fromhex(hex_id)
            
            decrypted = bytes([encrypted_part[j] ^ key[j % len(key)] for j in range(len(encrypted_part))])
            decoded = decrypted.decode('utf-8', errors='ignore')
            full_flag = 'CS{' + decoded
            
            # Check if it looks like a flag
            flag_match = re.search(r'CS\{[A-Za-z0-9_]+\}', full_flag)
            if flag_match:
                flag = flag_match.group(0)
                flag_content = flag[3:-1]
                
                # Check quality
                if len(flag_content) > 8:
                    alnum_count = sum(1 for c in flag_content if c.isalnum() or c == '_')
                    if alnum_count / len(flag_content) > 0.8:
                        matches_found.append((i, hex_id, knight_id, content[:50], flag, len(flag_content)))
        except:
            pass

if matches_found:
    print(f"\nFound {len(matches_found)} potential matches:")
    print("-" * 80)
    for hex_msg_num, hex_id, knight_id, content, flag, length in matches_found:
        print(f"Hex message {hex_msg_num}: {flag} (length: {length})")
        print(f"  Using hex ID: {hex_id} from [K-{knight_id}]")
        print(f"  Knight message: {content}...")
        print()
else:
    print("\nNo matches found with previous knight message hex IDs")

# Also try: maybe the hex ID from knight message at same index
print("\n" + "=" * 80)
print("TRYING: HEX MESSAGE[i] USES HEX ID FROM KNIGHT MESSAGE[i]")
print("=" * 80)

for i in range(min(50, len(hex_msgs), len(knight_msgs))):
    hex_time, hex_str = hex_msgs[i][1:]
    knight_time, hex_id, knight_id, content = knight_msgs[i][1:]
    
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
                alnum_count = sum(1 for c in flag_content if c.isalnum() or c == '_')
                if alnum_count / len(flag_content) > 0.9:
                    print(f"\nMessage {i+1}: {flag} (length: {len(flag_content)})")
                    print(f"  Hex ID: {hex_id} from [K-{knight_id}]")
                    print(f"  Content: {content[:60]}...")
    except:
        pass

