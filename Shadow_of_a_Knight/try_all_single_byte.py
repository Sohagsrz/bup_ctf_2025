#!/usr/bin/env python3
from scapy.all import rdpcap, Raw, TCP
import urllib.parse
import re

packets = rdpcap('capture.pcap')

# Get first hex-encoded message
hex_strings = []
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
                            hex_strings.append(decoded_msg)
        except:
            pass

if hex_strings:
    first_msg = bytes.fromhex(hex_strings[0])
    print(f"Testing first message: {len(first_msg)} bytes")
    print(f"Hex: {hex_strings[0][:60]}...")
    
    # Try all single-byte keys
    print("\nTrying all single-byte XOR keys...")
    found_readable = []
    
    for key in range(256):
        decrypted = bytes([b ^ key for b in first_msg])
        try:
            decoded = decrypted.decode('utf-8', errors='ignore')
            # Check if it's mostly printable and contains CS{
            if 'CS{' in decoded:
                flag_match = re.search(r'CS\{[^}]+\}', decoded)
                if flag_match:
                    print(f"\nKEY FOUND: 0x{key:02X} ({key})")
                    print(f"FLAG: {flag_match.group(0)}")
                    break
            # Also check if it's mostly readable
            printable_count = sum(1 for c in decoded if c.isprintable() or c in '\n\r\t')
            if printable_count > len(decoded) * 0.8:  # 80% printable
                found_readable.append((key, decoded[:100]))
        except:
            pass
    
    if found_readable:
        print(f"\nFound {len(found_readable)} readable decryptions:")
        for key, text in found_readable[:10]:  # Show first 10
            print(f"Key 0x{key:02X}: {text[:80]}...")

# Also try combining all messages and testing
print("\n" + "=" * 80)
print("COMBINING ALL MESSAGES AND TESTING")
print("=" * 80)

all_hex = ''.join(hex_strings)
all_bytes = bytes.fromhex(all_hex)

# Try single-byte XOR on combined
print("Trying single-byte XOR on combined data...")
for key in range(256):
    decrypted = bytes([b ^ key for b in all_bytes[:500]])  # First 500 bytes
    try:
        decoded = decrypted.decode('utf-8', errors='ignore')
        if 'CS{' in decoded:
            flag_match = re.search(r'CS\{[^}]+\}', decoded)
            if flag_match:
                print(f"\nKEY FOUND: 0x{key:02X} ({key})")
                print(f"FLAG: {flag_match.group(0)}")
                break
    except:
        pass

