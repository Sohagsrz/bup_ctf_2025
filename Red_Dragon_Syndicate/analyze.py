#!/usr/bin/env python3
from pwn import *

# Analyze the binary
context.binary = './binary'
context.arch = 'i386'
context.os = 'linux'

# Try to find the main function and understand the vulnerability
print("Binary analysis:")
print(f"Architecture: {context.arch}")
print(f"OS: {context.os}")

# Let's try to find buffer overflow point
# The challenge mentions executable stack, so we can use shellcode

