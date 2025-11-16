#!/usr/bin/env python3
"""
Since reverse doesn't work perfectly, try brute force with forward function
Test common flag patterns and see which encrypts closest to bucket_root
"""

from twist_final_correct import twist_forward

BUCKET_ROOT = bytes.fromhex('8729bd38a1de74707e01a544915154cf909398dd24bec96b695fea71e2')
KEY = 0x28c

# Common flag patterns
patterns = [
    "talk_to_me_please_again",
    "Talk_To_Me_Please_Again",
    "talktomepleaseagain",
    "please_talk_to_me",
    "talk_to_me_again",
    "talk_please_again",
]

print("Brute forcing with forward function...")
print(f"Target: {BUCKET_ROOT.hex()}")
print()

best_match = 0
best_flag = None

for pattern in patterns:
    # Try different padding to get 29 bytes
    for pad_len in range(0, 10):
        content = pattern + "_" * pad_len
        if len(content) == 25:
            flag = f"CS{{{content}}}"
            if len(flag) == 29:
                try:
                    encrypted = twist_forward(flag.encode(), KEY)
                    matches = sum(1 for a, b in zip(encrypted, BUCKET_ROOT) if a == b)
                    if matches > best_match:
                        best_match = matches
                        best_flag = flag
                        print(f"New best: {flag}")
                        print(f"  Matches: {matches}/29")
                        if matches == 29:
                            print(f"\n🎉 FOUND FLAG: {flag}")
                            exit(0)
                except:
                    pass

print(f"\nBest match: {best_match}/29")
if best_flag:
    print(f"Best flag: {best_flag}")


