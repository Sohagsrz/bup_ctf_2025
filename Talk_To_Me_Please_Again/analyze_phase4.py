#!/usr/bin/env python3
"""
Analyze phase 4 more carefully
Looking at assembly 1520-153a:
- rcx starts at 3
- rdi_limit = (length * 8) - length + 3
- Loop: rcx from 3 to rdi_limit in steps of 7
- divq %rsi -> rdx = rcx % length
- movzbl (%rsp,%rdx), %eax -> read from stack[rdx]
- movb %al, -0x1(%rbx) -> write to output[rbx-1]
- rbx increments by 1

So for length=29:
- rdi_limit = (29 * 8) - 29 + 3 = 232 - 29 + 3 = 206
- rcx goes: 3, 10, 17, 24, 31, 38, ..., up to < 206
- For each rcx: src_idx = rcx % 29, write to output[rbx-1] where rbx increments
"""

length = 29
rdi_limit = (length * 8) - length + 3
print(f"Length: {length}")
print(f"rdi_limit: {rdi_limit}")
print()

rcx_values = []
rbx = 0
rcx = 3

print("Phase 4 forward (what assembly does):")
print("rcx -> src_idx (rcx % length) -> output[rbx]")
while rcx < rdi_limit and rbx < length:
    src_idx = rcx % length
    rcx_values.append((rcx, src_idx, rbx))
    print(f"  rcx={rcx:3d} -> src_idx={src_idx:2d} -> output[{rbx:2d}] = stack[{src_idx:2d}]")
    rbx += 1
    rcx += 7

print(f"\nTotal iterations: {len(rcx_values)}")
print(f"rbx final: {rbx}")

# Now reverse
print("\n" + "="*60)
print("Phase 4 reverse (what we need to do):")
print("output[rbx] -> stack[src_idx]")
print()

# Reverse mapping
reverse_map = {}
for rcx, src_idx, rbx in rcx_values:
    reverse_map[rbx] = src_idx
    print(f"  output[{rbx:2d}] -> stack[{src_idx:2d}]")

# Check if all positions are covered
print(f"\nPositions covered: {sorted(reverse_map.keys())}")
if len(reverse_map) == length:
    print("✅ All positions covered")
else:
    print(f"⚠️  Only {len(reverse_map)}/{length} positions covered")
    missing = set(range(length)) - set(reverse_map.keys())
    print(f"Missing positions: {sorted(missing)}")

