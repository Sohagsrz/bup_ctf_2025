#!/usr/bin/env python3
"""
Test phase 3 forward and reverse to understand it better
"""

length = 29
r10 = 2

print("Phase 3 forward:")
print("rdi -> idx1=(r10+rdi)%len, idx2=rdi%len")
print("combined = (val1<<5)|(val2>>3)")
print("target = (rdi+1)%len")
print("stack[target] ^= combined")
print()

stack_forward = list(range(length))  # Test data
print("Forward operations:")
for rdi in range(length - 1):
    idx1 = (r10 + rdi) % length
    idx2 = rdi % length
    val1 = stack_forward[idx1]
    val2 = stack_forward[idx2]
    combined = ((val1 << 5) | (val2 >> 3)) & 0xff
    target = (rdi + 1) % length
    print(f"  rdi={rdi:2d}: idx1={idx1:2d}, idx2={idx2:2d}, target={target:2d}, combined=0x{combined:02x}")
    stack_forward[target] ^= combined

print("\nPhase 3 reverse:")
print("Need to reverse in opposite order")
print("For rdi from length-2 down to 0:")
print("  idx1=(r10+rdi)%len, idx2=rdi%len")
print("  combined = (val1<<5)|(val2>>3)")
print("  target = (rdi+1)%len")
print("  stack[target] ^= combined (XOR is its own inverse)")

# Test if reverse works
stack_reverse = stack_forward.copy()
print("\nReversing...")
for rdi in range(length - 2, -1, -1):
    idx1 = (r10 + rdi) % length
    idx2 = rdi % length
    val1 = stack_reverse[idx1]
    val2 = stack_reverse[idx2]
    combined = ((val1 << 5) | (val2 >> 3)) & 0xff
    target = (rdi + 1) % length
    stack_reverse[target] ^= combined

original = list(range(length))
print(f"\nOriginal: {original[:10]}...")
print(f"After forward: {stack_forward[:10]}...")
print(f"After reverse: {stack_reverse[:10]}...")
print(f"Match: {stack_reverse == original}")

