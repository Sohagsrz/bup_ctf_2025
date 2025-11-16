#!/usr/bin/env python3
from scapy.all import rdpcap, Raw, TCP, DNS
import urllib.parse
import re
import binascii

packets = rdpcap('capture.pcap')

# Extract hex-encoded POST messages
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
                            hex_part = decoded_msg[6:]  # Remove "43537B"
                            hex_strings.append(hex_part)
        except:
            pass

print(f"Found {len(hex_strings)} hex-encoded messages")

# Try combining all hex strings and decoding
all_hex = ''.join(hex_strings)
print(f"Total hex length: {len(all_hex)}")

try:
    combined_bytes = bytes.fromhex(all_hex)
    print(f"Combined bytes: {len(combined_bytes)} bytes")
    
    # Try to find readable text
    # Maybe it's encrypted with a simple XOR
    # Try XOR with single byte keys (limited range for common keys)
    print("\nTrying single-byte XOR keys (common ones)...")
    common_keys = [0x00, 0xFF, 0x42, 0x13, 0x37, 0x5A, 0xAA, 0x55, 0x01, 0x02, 0x03, 0x04, 0x05]
    for key in common_keys:
        xor_result = bytes([b ^ key for b in combined_bytes[:200]])
        try:
            decoded = xor_result.decode('utf-8', errors='ignore')
            if 'CS{' in decoded or 'flag' in decoded.lower() or any(c.isprintable() for c in decoded[:50]):
                print(f"Key {key:02X} ({key}): {decoded[:200]}")
        except:
            pass
    
    # Maybe it's base64 encoded
    import base64
    try:
        b64_decoded = base64.b64decode(combined_bytes)
        b64_text = b64_decoded.decode('utf-8', errors='ignore')
        if 'CS{' in b64_text:
            print(f"\nBase64 decoded: {b64_text[:500]}")
    except:
        pass
    
except Exception as e:
    print(f"Error: {e}")

# Also check DNS queries for any other patterns
print("\n" + "=" * 80)
print("CHECKING DNS QUERIES FOR PATTERNS")
print("=" * 80)

dns_subdomains = []
for packet in packets:
    if packet.haslayer(DNS):
        dns = packet[DNS]
        if dns.qr == 0:
            query_name = dns.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
            parts = query_name.split('.')
            if len(parts) > 1:
                subdomain = parts[0]
                # Filter out red herrings
                if not subdomain.startswith('43537B') and subdomain not in ['neverssl', 'github', 'any', 'malwarebytes', 'knightsquad', 'nomanprodhan']:
                    dns_subdomains.append(subdomain)

# Look for patterns in DNS subdomains
print(f"Found {len(dns_subdomains)} DNS subdomains (filtered)")

# Try to see if any decode to readable text
print("\nTrying to decode DNS subdomains...")
for subdomain in dns_subdomains[:20]:
    # Try hex
    if len(subdomain) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in subdomain):
        try:
            decoded = bytes.fromhex(subdomain).decode('utf-8', errors='ignore')
            if decoded.isprintable() and len(decoded) > 1:
                print(f"{subdomain} -> {decoded}")
        except:
            pass

