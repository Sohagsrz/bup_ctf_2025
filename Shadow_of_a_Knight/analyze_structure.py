#!/usr/bin/env python3
from scapy.all import rdpcap, Raw, TCP
import urllib.parse
import re
from collections import Counter

packets = rdpcap('capture.pcap')

# Extract hex-encoded messages
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

print(f"Found {len(hex_strings)} hex-encoded messages")

# Analyze the structure
if hex_strings:
    first_msg = bytes.fromhex(hex_strings[0])
    print(f"\nFirst message structure:")
    print(f"  Length: {len(first_msg)} bytes")
    print(f"  Starts with: {first_msg[:5]}")
    print(f"  Hex: {hex_strings[0][:60]}...")
    
    # Check if all messages have the same structure
    lengths = [len(bytes.fromhex(h)) for h in hex_strings]
    print(f"\nMessage lengths: min={min(lengths)}, max={max(lengths)}, unique={len(set(lengths))}")
    
    # Check first few bytes of each message
    print("\nFirst 10 bytes of first 10 messages:")
    for i, hex_str in enumerate(hex_strings[:10], 1):
        msg_bytes = bytes.fromhex(hex_str)
        print(f"{i}. {msg_bytes[:10].hex()} -> {msg_bytes[:10]}")
    
    # Check if first 3 bytes are always CS{
    all_start_cs = all(bytes.fromhex(h)[:3] == b'CS{' for h in hex_strings)
    print("\nAll messages start with CS{: " + str(all_start_cs))
    
    # Analyze byte patterns - maybe the key is in the data itself
    print("\nAnalyzing byte patterns...")
    # Get bytes after CS{
    after_cs = [bytes.fromhex(h)[3:] for h in hex_strings]
    
    # Check if there are common patterns
    print(f"Bytes after CS{{: length={len(after_cs[0])}")
    print(f"First message after CS{{: {after_cs[0][:20].hex()}")
    
    # Maybe try XOR with the first few bytes as key
    print("\nTrying XOR with first few bytes as key...")
    for key_len in [4, 8, 12, 16]:
        key = after_cs[0][:key_len]
        decrypted = bytes([after_cs[0][i] ^ key[i % len(key)] for i in range(len(after_cs[0]))])
        try:
            decoded = decrypted.decode('utf-8', errors='ignore')
            if 'CS{' in decoded or any(c.isprintable() for c in decoded[:20]):
                print(f"Key length {key_len}: {decoded[:100]}")
        except:
            pass

# Try looking for the key in DNS queries
print("\n" + "=" * 80)
print("LOOKING FOR KEY IN DNS QUERIES")
print("=" * 80)

from scapy.all import DNS

dns_subdomains = []
for packet in packets:
    if packet.haslayer(DNS):
        dns = packet[DNS]
        if dns.qr == 0:
            query_name = dns.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
            parts = query_name.split('.')
            if len(parts) > 1:
                subdomain = parts[0]
                if subdomain not in ['neverssl', 'github', 'any', 'malwarebytes', 'knightsquad', 'nomanprodhan'] and not subdomain.startswith('43537B'):
                    dns_subdomains.append(subdomain)

# Try using DNS subdomains as keys
print(f"Found {len(dns_subdomains)} DNS subdomains")
print("Trying first 20 DNS subdomains as keys...")

for subdomain in dns_subdomains[:20]:
    if len(subdomain) < 4:
        continue
    key = subdomain.encode('utf-8')
    msg_bytes = bytes.fromhex(hex_strings[0])
    decrypted = bytes([msg_bytes[j] ^ key[j % len(key)] for j in range(len(msg_bytes))])
    try:
        decoded = decrypted.decode('utf-8', errors='ignore')
        if 'CS{' in decoded:
            flag_match = re.search(r'CS\{[^}]+\}', decoded)
            if flag_match:
                print(f"\nKEY FOUND: {subdomain}")
                print(f"FLAG: {flag_match.group(0)}")
                break
    except:
        pass

