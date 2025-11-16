#!/usr/bin/env python3
from scapy.all import rdpcap, Raw, TCP
import urllib.parse
import re
import binascii

packets = rdpcap('capture.pcap')

print("=" * 80)
print("EXTRACTING HEX DATA FROM POST MESSAGES")
print("=" * 80)

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
                        
                        # Check if it starts with hex pattern (CS{ = 43537B)
                        if decoded_msg.startswith('43537B'):
                            # Extract hex part (everything after "43537B")
                            hex_part = decoded_msg[6:]  # Remove "43537B" prefix
                            hex_strings.append(hex_part)
        except:
            pass

print(f"Found {len(hex_strings)} hex-encoded messages starting with CS{{")

# Try to decode each hex string
print("\n" + "=" * 80)
print("DECODING HEX STRINGS")
print("=" * 80)

decoded_strings = []
for i, hex_str in enumerate(hex_strings[:10], 1):  # First 10 for testing
    try:
        # Try to decode as hex
        hex_bytes = bytes.fromhex(hex_str)
        # Try to decode as UTF-8
        try:
            decoded = hex_bytes.decode('utf-8')
            print(f"{i}. {hex_str[:40]}... -> {decoded[:100]}")
            decoded_strings.append(decoded)
        except:
            # If not UTF-8, show as hex
            print(f"{i}. {hex_str[:40]}... -> (binary, {len(hex_bytes)} bytes)")
            decoded_strings.append(hex_bytes)
    except Exception as e:
        print(f"{i}. {hex_str[:40]}... -> ERROR: {e}")

# Try combining all hex strings
print("\n" + "=" * 80)
print("COMBINING ALL HEX STRINGS")
print("=" * 80)

all_hex = ''.join(hex_strings)
print(f"Total hex length: {len(all_hex)}")

# Try to decode the combined hex
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
        
        # Try to find patterns
        # Maybe it's encrypted or needs XOR
        print("\nTrying XOR with different keys...")
        for key in [0x00, 0xFF, 0x42, 0x13, 0x37]:
            xor_result = bytes([b ^ key for b in combined_bytes[:100]])
            try:
                decoded = xor_result.decode('utf-8', errors='ignore')
                if any(c.isprintable() for c in decoded):
                    print(f"XOR {key:02X}: {decoded[:100]}")
            except:
                pass
except Exception as e:
    print(f"Error decoding combined hex: {e}")

# Maybe the hex strings need to be decoded individually and concatenated
print("\n" + "=" * 80)
print("DECODING EACH HEX STRING INDIVIDUALLY AND CONCATENATING")
print("=" * 80)

individual_decoded = []
for hex_str in hex_strings:
    try:
        hex_bytes = bytes.fromhex(hex_str)
        # Try UTF-8
        try:
            decoded = hex_bytes.decode('utf-8')
            individual_decoded.append(decoded)
        except:
            # If not UTF-8, try to find printable chars
            decoded = hex_bytes.decode('utf-8', errors='ignore')
            if any(c.isprintable() for c in decoded):
                individual_decoded.append(decoded)
            else:
                individual_decoded.append('')
    except:
        individual_decoded.append('')

combined_text = ''.join(individual_decoded)
print(f"Combined length: {len(combined_text)}")
print(f"\nFirst 500 chars:\n{combined_text[:500]}")
print(f"\nLast 500 chars:\n{combined_text[-500:]}")

# Look for flag
flag_match = re.search(r'CS\{[^}]+\}', combined_text)
if flag_match:
    print(f"\nFLAG FOUND: {flag_match.group(0)}")

