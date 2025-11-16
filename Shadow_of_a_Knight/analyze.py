#!/usr/bin/env python3
from scapy.all import rdpcap, DNS, IP, IPv6
import re

# Read the pcap file
packets = rdpcap('capture.pcap')

dns_queries = []
http_requests = []

print(f"Total packets: {len(packets)}\n")

# Extract DNS queries
for packet in packets:
    if packet.haslayer(DNS):
        dns = packet[DNS]
        if dns.qr == 0:  # Query (not response)
            query_name = dns.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
            dns_queries.append(query_name)
            print(f"DNS Query: {query_name}")

print(f"\n\nTotal DNS queries: {len(dns_queries)}\n")

# Look for patterns in DNS queries
print("=" * 80)
print("Analyzing DNS queries for hidden data...")
print("=" * 80)

# Extract subdomain parts that might contain encoded data
suspicious_domains = []
for query in dns_queries:
    parts = query.split('.')
    if len(parts) > 1:
        subdomain = parts[0]
        suspicious_domains.append(subdomain)
        print(f"Subdomain: {subdomain}")

print("\n" + "=" * 80)
print("Extracted subdomains (potential encoded data):")
print("=" * 80)
for i, subdomain in enumerate(suspicious_domains, 1):
    print(f"{i}. {subdomain}")

# Try to decode as base64 or hex
print("\n" + "=" * 80)
print("Attempting to decode subdomains...")
print("=" * 80)

import base64
import binascii

decoded_data = []
for subdomain in suspicious_domains:
    # Try base64
    try:
        # Add padding if needed
        padded = subdomain + '=' * (4 - len(subdomain) % 4)
        decoded = base64.b64decode(padded)
        if decoded.isprintable():
            decoded_data.append(decoded.decode('utf-8', errors='ignore'))
            print(f"{subdomain} -> Base64: {decoded.decode('utf-8', errors='ignore')}")
    except:
        pass
    
    # Try hex
    try:
        decoded = bytes.fromhex(subdomain)
        if decoded.isprintable():
            decoded_data.append(decoded.decode('utf-8', errors='ignore'))
            print(f"{subdomain} -> Hex: {decoded.decode('utf-8', errors='ignore')}")
    except:
        pass

# Also check HTTP traffic
print("\n" + "=" * 80)
print("Checking HTTP traffic...")
print("=" * 80)

from scapy.all import Raw, TCP

for packet in packets:
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        try:
            raw_data = packet[Raw].load.decode('utf-8', errors='ignore')
            if 'HTTP' in raw_data or 'GET' in raw_data or 'POST' in raw_data:
                print(raw_data[:200])
                http_requests.append(raw_data)
        except:
            pass

