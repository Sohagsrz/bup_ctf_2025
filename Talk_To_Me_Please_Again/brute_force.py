#!/usr/bin/env python3
"""
Brute force approach with constraints
"""

import itertools
import string

KDATA = [
    0xa3d94f21, 0x55ccaa01, 0x12345678, 0xdeadbeef,
    0x0f1e2d3c, 0xcafebabe, 0xfeedface, 0x01020304,
    0x89abcdef, 0x13579bdf, 0x2468ace0, 0x0badf00d,
    0x31415926, 0x27182818, 0xb16b00b5, 0x0c0ffee0,
    0xf00dbaaa, 0xbaadf00d, 0xabcd1234, 0x0defaced,
    0xc001d00d, 0xfeedf00d, 0xdeadc0de, 0x1337c0de
]

BUCKET_ROOT = bytes.fromhex('8729bd38a1de74707e01a544915154cf909398dd24bec96b695fea71e2')
KEY = 0x28c

# Try to use the forward function from twist_precise
import sys
sys.path.insert(0, '.')
from twist_precise import twist_block_forward

def brute_force_systematic():
    """Try systematic brute force with constraints"""
    prefix = b"CS{"
    suffix = b"}"
    middle_len = 29 - len(prefix) - len(suffix)  # 25 characters
    
    print(f"Need to find {middle_len} characters")
    print(f"Target hash: {BUCKET_ROOT.hex()}")
    print()
    
    # Try common CTF patterns
    common_patterns = [
        b"talk_to_me_please_again",
        b"talk_to_me_please_again!",
        b"talk_to_me_please_again!!",
        b"talk_to_me_please_again!!!",
        b"talk_to_me_please_again!!!!",
        b"talk_to_me_please_again!!!!!",
        b"talk_to_me_please_again!!!!!!",
        b"talk_to_me_please_again!!!!!!!",
        b"talk_to_me_please_again!!!!!!!!",
        b"talk_to_me_please_again!!!!!!!!!",
        b"talk_to_me_please_again!!!!!!!!!!",
        b"talk_to_me_please_again!!!!!!!!!!!",
        b"talk_to_me_please_again!!!!!!!!!!!!",
        b"talk_to_me_please_again!!!!!!!!!!!!!",
        b"talk_to_me_please_again!!!!!!!!!!!!!!",
        b"talk_to_me_please_again!!!!!!!!!!!!!!!",
        b"talk_to_me_please_again!!!!!!!!!!!!!!!!",
        b"talk_to_me_please_again!!!!!!!!!!!!!!!!!",
        b"talk_to_me_please_again!!!!!!!!!!!!!!!!!!",
        b"talk_to_me_please_again!!!!!!!!!!!!!!!!!!!",
        b"talk_to_me_please_again!!!!!!!!!!!!!!!!!!!!",
        b"talk_to_me_please_again!!!!!!!!!!!!!!!!!!!!!",
        b"talk_to_me_please_again!!!!!!!!!!!!!!!!!!!!!!",
        b"talk_to_me_please_again!!!!!!!!!!!!!!!!!!!!!!!",
        b"talk_to_me_please_again!!!!!!!!!!!!!!!!!!!!!!!!",
    ]
    
    # Also try variations
    base = "talk_to_me_please_again"
    variations = []
    for i in range(25 - len(base) + 1):
        if i == 0:
            test = base
        else:
            test = base + "_" * i
        if len(test) <= 25:
            test = test.ljust(25, "_")
            variations.append(test.encode())
    
    all_patterns = common_patterns + variations
    
    print(f"Trying {len(all_patterns)} patterns...")
    for i, pattern in enumerate(all_patterns):
        if len(pattern) == middle_len:
            test = prefix + pattern + suffix
            if len(test) == 29:
                try:
                    encrypted = twist_block_forward(test, KEY)
                    if encrypted == BUCKET_ROOT:
                        print(f"\n🎉 FOUND FLAG: {test.decode('ascii', errors='ignore')}")
                        return test.decode('ascii', errors='ignore')
                    elif i % 100 == 0:
                        print(f"Tried {i} patterns...")
                except Exception as e:
                    pass
    
    # Try with printable characters
    print("\nTrying with printable characters...")
    charset = string.ascii_lowercase + string.digits + "_"
    
    # Try shorter patterns first
    for length in range(20, 26):
        print(f"Trying length {length}...")
        # This would take too long, so let's be smart
        # Try common words
        common_words = [
            b"talk", b"to", b"me", b"please", b"again",
            b"secret", b"flag", b"code", b"key", b"pass"
        ]
        
        # Try combinations
        for combo in itertools.product(common_words, repeat=3):
            test_str = b"_".join(combo)
            if len(test_str) == length:
                test = prefix + test_str + suffix
                if len(test) == 29:
                    try:
                        encrypted = twist_block_forward(test, KEY)
                        if encrypted == BUCKET_ROOT:
                            print(f"\n🎉 FOUND FLAG: {test.decode('ascii', errors='ignore')}")
                            return test.decode('ascii', errors='ignore')
                    except:
                        pass
    
    return None


if __name__ == "__main__":
    result = brute_force_systematic()
    if not result:
        print("\n❌ Could not find flag with brute force")
        print("Need more accurate twist_block implementation")

