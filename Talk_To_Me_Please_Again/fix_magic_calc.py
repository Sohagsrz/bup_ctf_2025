#!/usr/bin/env python3
"""
Fix the magic number calculation for phase 2
"""

MAGIC = 0xAAAAAAAAAAAAAAAB

def calculate_kdata_idx_phase2_correct(r9_val):
    """Correct calculation from assembly"""
    # Assembly does:
    # mulq %r13 (MAGIC) -> result in rdx:rax (128-bit)
    # shrq $0x4, %rdx -> shift high 64 bits right by 4
    # leaq (%rdx,%rdx,2), %rax -> rax = rdx * 3
    # shlq $0x3, %rax -> rax = rax * 8 (total: rdx * 24)
    # subq %rax, %rdx -> rdx = rdx - rax
    # mov edx, [rbp+rdx*4] -> KDATA[rdx]
    
    val = r9_val & 0xFFFFFFFFFFFFFFFF
    
    # Multiply by MAGIC - in Python, this gives us a 128-bit result
    # We need to simulate the 64-bit x 64-bit = 128-bit multiplication
    # For small values, we can use Python's arbitrary precision
    product = val * MAGIC
    
    # Get high 64 bits (bits 64-127)
    # In Python, we need to extract this correctly
    high_bits = (product >> 64) & 0xFFFFFFFFFFFFFFFF
    
    # Shift right by 4
    shifted = high_bits >> 4
    
    # Multiply by 3, then by 8 (total: multiply by 24)
    offset = ((shifted + (shifted << 1)) << 3) & 0xFFFFFFFFFFFFFFFF
    
    # Subtract
    result = (val - offset) & 0xFFFFFFFFFFFFFFFF
    
    # The result should be modulo 24
    return result % 24

# Test
print("Testing correct magic number calculation:")
r9 = (0x28c >> 8) & 0xFF  # 0x02
for i in range(10):
    idx = calculate_kdata_idx_phase2_correct(r9)
    simple = (r9 * 3) % 24
    print(f"r9=0x{r9:02x}: magic_idx={idx:2d}, simple={simple:2d}, match={idx==simple}")
    r9 = (r9 + 3) & 0xFF

# The key insight: if magic calculation != simple modulo,
# then we MUST use the magic calculation!

