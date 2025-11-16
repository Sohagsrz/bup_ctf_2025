#!/usr/bin/env python3
from scapy.all import rdpcap, Raw, TCP
import urllib.parse
import re
import string

packets = rdpcap('capture.pcap')

# Get hex-encoded messages
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

# Try to find a clean flag
print("\nSearching for clean flags...")
clean_flags = []

for i, hex_str in enumerate(hex_strings, 1):
    msg_bytes = bytes.fromhex(hex_str)
    encrypted_part = msg_bytes[3:]
    
    # Try single-byte XOR
    for key in range(256):
        decrypted = bytes([b ^ key for b in encrypted_part])
        try:
            decoded = decrypted.decode('utf-8', errors='ignore')
            full_flag = 'CS{' + decoded
            
            # Check if it's a valid flag format
            flag_match = re.search(r'CS\{[^}]+\}', full_flag)
            if flag_match:
                flag = flag_match.group(0)
                flag_content = flag[3:-1]
                
                # Check if it looks like a real flag (alphanumeric and underscores)
                if len(flag_content) > 5:
                    # Count printable ASCII characters
                    printable = sum(1 for c in flag_content if c in string.printable)
                    alnum_underscore = sum(1 for c in flag_content if c.isalnum() or c == '_')
                    
                    # If mostly alphanumeric/underscore, it's likely a real flag
                    if alnum_underscore > len(flag_content) * 0.7:
                        clean_flags.append((i, key, flag))
                        print(f"Message {i}, Key 0x{key:02X}: {flag}")
        except:
            pass

if clean_flags:
    print(f"\nFound {len(clean_flags)} potential clean flags")
    # Show unique flags
    unique_flags = list(set([f[2] for f in clean_flags]))
    print(f"\nUnique flags found:")
    for flag in unique_flags:
        print(f"  {flag}")
        
    # If we found a flag that looks real, use it
    for flag in unique_flags:
        flag_content = flag[3:-1]
        if all(c.isalnum() or c == '_' for c in flag_content):
            print(f"\n*** MOST LIKELY FLAG: {flag} ***")
            break
else:
    print("\nNo clean flags found. Trying different approaches...")
    
    # Maybe the flag is split across messages
    print("\nTrying to combine messages...")
    # Get first few messages and try combining them
    combined_encrypted = b''.join([bytes.fromhex(h)[3:] for h in hex_strings[:10]])
    
    for key in range(256):
        decrypted = bytes([b ^ key for b in combined_encrypted[:100]])
        try:
            decoded = decrypted.decode('utf-8', errors='ignore')
            if 'CS{' in decoded or '}' in decoded:
                flag_match = re.search(r'CS\{[^}]+\}', 'CS{' + decoded)
                if flag_match:
                    flag = flag_match.group(0)
                    flag_content = flag[3:-1]
                    if all(c.isalnum() or c == '_' for c in flag_content) and len(flag_content) > 5:
                        print(f"\nCombined, Key 0x{key:02X}: {flag}")
                        break
        except:
            pass

