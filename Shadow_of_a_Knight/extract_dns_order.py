#!/usr/bin/env python3
from scapy.all import rdpcap, DNS
import binascii
import re

packets = rdpcap('capture.pcap')

print("=" * 80)
print("EXTRACTING DNS QUERIES IN ORDER")
print("=" * 80)

dns_queries = []
for packet in packets:
    if packet.haslayer(DNS):
        dns = packet[DNS]
        if dns.qr == 0:  # Query
            query_name = dns.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
            timestamp = float(packet.time)
            parts = query_name.split('.')
            if len(parts) > 1:
                subdomain = parts[0]
                dns_queries.append((timestamp, subdomain, query_name))

# Sort by timestamp
dns_queries.sort(key=lambda x: x[0])

print(f"Found {len(dns_queries)} DNS queries\n")

# Extract subdomains in order
subdomains = [q[1] for q in dns_queries]

# Look for hex-encoded subdomains
hex_subdomains = []
for subdomain in subdomains:
    # Check if it looks like hex (only hex chars, even length, reasonable length)
    if len(subdomain) >= 4 and len(subdomain) % 2 == 0:
        if all(c in '0123456789abcdefABCDEF' for c in subdomain):
            hex_subdomains.append(subdomain)

print(f"Found {len(hex_subdomains)} hex-encoded subdomains\n")

# Try to decode hex subdomains
print("=" * 80)
print("DECODING HEX SUBDOMAINS")
print("=" * 80)

decoded_parts = []
for hex_sub in hex_subdomains:
    try:
        decoded_bytes = bytes.fromhex(hex_sub)
        # Try UTF-8
        try:
            decoded = decoded_bytes.decode('utf-8')
            if decoded.isprintable():
                decoded_parts.append(decoded)
                print(f"{hex_sub} -> {decoded}")
        except:
            # Try to find printable parts
            decoded = decoded_bytes.decode('utf-8', errors='ignore')
            if any(c.isprintable() for c in decoded):
                decoded_parts.append(decoded)
                print(f"{hex_sub} -> {decoded}")
    except:
        pass

# Combine decoded parts
if decoded_parts:
    combined = ''.join(decoded_parts)
    print(f"\nCombined decoded subdomains ({len(combined)} chars):")
    print(combined[:500])
    
    # Look for flag
    flag_match = re.search(r'CS\{[^}]+\}', combined)
    if flag_match:
        print(f"\nFLAG FOUND: {flag_match.group(0)}")

# Also try combining all hex subdomains as one big hex string
print("\n" + "=" * 80)
print("COMBINING ALL HEX SUBDOMAINS AS ONE HEX STRING")
print("=" * 80)

all_hex = ''.join(hex_subdomains)
print(f"Total hex length: {len(all_hex)}")

try:
    combined_bytes = bytes.fromhex(all_hex)
    print(f"Combined bytes length: {len(combined_bytes)}")
    
    # Try UTF-8
    try:
        combined_text = combined_bytes.decode('utf-8')
        print(f"\nCombined text (first 500 chars):\n{combined_text[:500]}")
        
        # Look for flag
        flag_match = re.search(r'CS\{[^}]+\}', combined_text)
        if flag_match:
            print(f"\nFLAG FOUND: {flag_match.group(0)}")
    except:
        print("Not valid UTF-8")
except Exception as e:
    print(f"Error: {e}")

# Maybe filter out the red herring flags
print("\n" + "=" * 80)
print("FILTERING OUT RED HERRING FLAGS")
print("=" * 80)

filtered_hex = [h for h in hex_subdomains if not h.startswith('43537B')]
print(f"After filtering: {len(filtered_hex)} hex subdomains")

if filtered_hex:
    all_hex_filtered = ''.join(filtered_hex)
    print(f"Total hex length: {len(all_hex_filtered)}")
    
    try:
        combined_bytes = bytes.fromhex(all_hex_filtered)
        combined_text = combined_bytes.decode('utf-8', errors='ignore')
        print(f"\nCombined text (first 500 chars):\n{combined_text[:500]}")
        
        flag_match = re.search(r'CS\{[^}]+\}', combined_text)
        if flag_match:
            print(f"\nFLAG FOUND: {flag_match.group(0)}")
    except:
        pass

