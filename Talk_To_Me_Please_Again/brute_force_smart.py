#!/usr/bin/env python3
"""
Smart brute force: Try common flag patterns and see which one encrypts closest to bucket_root
"""

from twist_final_working import twist_block_forward

BUCKET_ROOT = bytes.fromhex('8729bd38a1de74707e01a544915154cf909398dd24bec96b695fea71e2')
KEY = 0x28c

# Common flag patterns to try
patterns = [
    "talk_to_me_please_again",
    "Talk_To_Me_Please_Again",
    "talktomepleaseagain",
    "please_talk_to_me",
    "talk_to_me_again",
    "talk_please_again",
    "let_me_talk_to_you",
    "can_we_talk_please",
]

print("Trying flag patterns...")
print(f"Target: {BUCKET_ROOT.hex()}")
print()

best_match = 0
best_flag = None

for pattern in patterns:
    # Try different padding to get 29 bytes
    for padding in ["", "!", "!!", "!!!", "!!!!", "!!!!!"]:
        flag_candidate = f"CS{{{pattern}{padding}}}"
        if len(flag_candidate) == 29:
            try:
                encrypted = twist_block_forward(flag_candidate.encode(), KEY)
                matches = sum(1 for a, b in zip(encrypted, BUCKET_ROOT) if a == b)
                
                if matches > best_match:
                    best_match = matches
                    best_flag = flag_candidate
                    print(f"New best: {flag_candidate}")
                    print(f"  Matches: {matches}/29")
                    print(f"  Encrypted: {encrypted.hex()[:40]}...")
                    
                    if matches == 29:
                        print(f"\n🎉 FOUND FLAG: {flag_candidate}")
                        exit(0)
            except Exception as e:
                pass

print(f"\nBest match: {best_match}/29")
if best_flag:
    print(f"Best flag: {best_flag}")

