#!/usr/bin/env python3
from scapy.all import rdpcap, DNS, Raw, TCP
import urllib.parse
import binascii
import re

packets = rdpcap('capture.pcap')

print("=" * 80)
print("EXTRACTING AND DECODING HEX DATA FROM DNS SUBDOMAINS")
print("=" * 80)

hex_subdomains = []
for packet in packets:
    if packet.haslayer(DNS):
        dns = packet[DNS]
        if dns.qr == 0:  # Query
            query_name = dns.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
            parts = query_name.split('.')
            if len(parts) > 1:
                subdomain = parts[0]
                # Check if it looks like hex (only hex chars, even length)
                if len(subdomain) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in subdomain):
                    try:
                        decoded = bytes.fromhex(subdomain).decode('utf-8', errors='ignore')
                        if any(c.isprintable() for c in decoded):
                            hex_subdomains.append((subdomain, decoded))
                            print(f"{subdomain} -> {decoded}")
                    except:
                        pass

print("\n" + "=" * 80)
print("EXTRACTING AND DECODING HEX DATA FROM POST MESSAGES")
print("=" * 80)

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
                        
                        # Check if it starts with hex pattern (CS{ = 43537B)
                        if decoded_msg.startswith('43537B'):
                            # Extract hex part
                            hex_part = decoded_msg[6:]  # Remove "43537B" prefix
                            try:
                                # Try to decode as hex
                                hex_bytes = bytes.fromhex(hex_part)
                                decoded_hex = hex_bytes.decode('utf-8', errors='ignore')
                                hex_messages.append(decoded_hex)
                                print(f"Message: {decoded_hex[:100]}...")
                            except:
                                pass
        except:
            pass

print(f"\nFound {len(hex_messages)} hex-encoded messages")

print("\n" + "=" * 80)
print("COMBINING ALL HEX MESSAGES")
print("=" * 80)

combined = ''.join(hex_messages)
print(f"\nCombined length: {len(combined)}")
print(f"\nFirst 500 chars:\n{combined[:500]}")
print(f"\nLast 500 chars:\n{combined[-500:]}")

# Look for flag pattern
if 'CS{' in combined:
    print("\n" + "=" * 80)
    print("FLAG FOUND!")
    print("=" * 80)
    flag_match = re.search(r'CS\{[^}]+\}', combined)
    if flag_match:
        print(f"\nFLAG: {flag_match.group(0)}")

