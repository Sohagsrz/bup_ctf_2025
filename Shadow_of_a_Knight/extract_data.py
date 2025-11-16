#!/usr/bin/env python3
from scapy.all import rdpcap, DNS, IP, Raw, TCP
import urllib.parse
import base64
import re

packets = rdpcap('capture.pcap')

print("=" * 80)
print("EXTRACTING DNS QUERIES")
print("=" * 80)

dns_subdomains = []
for packet in packets:
    if packet.haslayer(DNS):
        dns = packet[DNS]
        if dns.qr == 0:  # Query
            query_name = dns.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
            parts = query_name.split('.')
            if len(parts) > 1:
                subdomain = parts[0]
                dns_subdomains.append(subdomain)

print(f"Found {len(dns_subdomains)} DNS subdomains")
print("\nFirst 20 subdomains:")
for i, sub in enumerate(dns_subdomains[:20], 1):
    print(f"{i}. {sub}")

print("\n" + "=" * 80)
print("EXTRACTING POST REQUESTS TO secret-messages.php")
print("=" * 80)

secret_messages = []
for packet in packets:
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        try:
            raw_data = packet[Raw].load
            if b'POST /secret-messages.php' in raw_data:
                # Extract the message parameter
                data_str = raw_data.decode('utf-8', errors='ignore')
                if 'message=' in data_str:
                    # Find the message parameter
                    match = re.search(r'message=([^\s&]+)', data_str)
                    if match:
                        encoded_msg = match.group(1)
                        decoded_msg = urllib.parse.unquote(encoded_msg)
                        secret_messages.append(decoded_msg)
                        print(f"Found message: {decoded_msg[:100]}...")
        except:
            pass

print(f"\nFound {len(secret_messages)} secret messages")

print("\n" + "=" * 80)
print("ANALYZING DNS SUBDOMAINS FOR ENCODED DATA")
print("=" * 80)

# Try to decode all subdomains
decoded_parts = []
for subdomain in dns_subdomains:
    # Try base64
    try:
        # Add padding
        for pad_len in range(4):
            try:
                padded = subdomain + '=' * pad_len
                decoded = base64.b64decode(padded)
                if all(32 <= b <= 126 for b in decoded):  # Printable ASCII
                    decoded_str = decoded.decode('utf-8', errors='ignore')
                    decoded_parts.append(decoded_str)
                    print(f"{subdomain} -> Base64: {decoded_str}")
                    break
            except:
                continue
    except:
        pass

print("\n" + "=" * 80)
print("COMBINING ALL SECRET MESSAGES")
print("=" * 80)

for i, msg in enumerate(secret_messages, 1):
    print(f"\nMessage {i}:")
    print(msg)

