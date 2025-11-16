#!/usr/bin/env python3
"""
Look for patterns in knight messages that might indicate which hex ID to use
Also check if hex IDs appear in a specific order or pattern
"""
from scapy.all import rdpcap, Raw, TCP
import urllib.parse
import re

packets = rdpcap('capture.pcap')

# Extract messages in order
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
                                all_messages.append(('knight', timestamp, hex_id, knight_id, content))
        except:
            pass

all_messages.sort(key=lambda x: x[1])

# Analyze the pattern
print("=" * 80)
print("ANALYZING MESSAGE PATTERNS")
print("=" * 80)

# Count messages
knight_count = sum(1 for m in all_messages if m[0] == 'knight')
hex_count = sum(1 for m in all_messages if m[0] == 'hex')

print(f"\nKnight messages: {knight_count}")
print(f"Hex messages: {hex_count}")
print(f"Ratio: ~{knight_count/hex_count:.2f} hex messages per knight message")

# Look at the sequence around first hex message
print("\n" + "=" * 80)
print("MESSAGES AROUND FIRST HEX MESSAGE")
print("=" * 80)

first_hex_idx = None
for i, msg in enumerate(all_messages):
    if msg[0] == 'hex':
        first_hex_idx = i
        break

if first_hex_idx:
    print(f"\nFirst hex message at index {first_hex_idx}")
    print("\nMessages before first hex (last 10):")
    for i in range(max(0, first_hex_idx - 10), first_hex_idx):
        msg = all_messages[i]
        if msg[0] == 'knight':
            timestamp, hex_id, knight_id, content = msg[1:]
            print(f"  [{i}] K-{knight_id}, Hex ID: {hex_id}")
            print(f"      {content[:60]}...")
    
    print(f"\nFirst hex message:")
    hex_time, hex_str = all_messages[first_hex_idx][1:]
    print(f"  Hex: {hex_str[:60]}...")
    
    # Try hex IDs from the last few knight messages
    print("\n" + "=" * 80)
    print("TRYING HEX IDs FROM LAST 5 KNIGHT MESSAGES BEFORE FIRST HEX")
    print("=" * 80)
    
    for i in range(max(0, first_hex_idx - 5), first_hex_idx):
        msg = all_messages[i]
        if msg[0] == 'knight':
            timestamp, hex_id, knight_id, content = msg[1:]
            
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
                        if alnum / len(flag_content) > 0.85:
                            print(f"\nHex ID {hex_id} from [K-{knight_id}]:")
                            print(f"  Flag: {flag} (length: {len(flag_content)})")
                            print(f"  Content: {content[:60]}...")
            except:
                pass

# Also check if there's a pattern in hex ID sequence
print("\n" + "=" * 80)
print("CHECKING HEX ID SEQUENCE PATTERN")
print("=" * 80)

knight_list = [m for m in all_messages if m[0] == 'knight']
hex_list = [m for m in all_messages if m[0] == 'hex']

print(f"\nFirst 10 knight hex IDs: {[m[2] for m in knight_list[:10]]}")
print(f"First 10 hex messages: {[m[2][:20] + '...' for m in hex_list[:10]]}")

# Try: hex message i uses hex ID from knight message at position i % len(knight_list)
print("\nTrying: hex[i] uses hex ID from knight[i % len(knight_list)]")
for i in range(min(20, len(hex_list))):
    hex_str = hex_list[i][2]
    knight_idx = i % len(knight_list)
    hex_id = knight_list[knight_idx][2]
    
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
            if len(flag_content) > 12 and all(c.isalnum() or c == '_' for c in flag_content):
                print(f"\nMessage {i+1}: {flag}")
                print(f"  Hex ID: {hex_id} (from knight[{knight_idx}])")
    except:
        pass

