#!/usr/bin/env python3
"""
Generate more comprehensive flag candidates
"""

def generate_all_candidates():
    """Generate all possible flag candidates"""
    candidates = []
    
    # Base patterns from challenge name
    bases = [
        "talk_to_me_please_again",
        "Talk_To_Me_Please_Again",
        "talktomepleaseagain",
        "please_talk_to_me",
        "talk_please_again",
        "let_me_talk",
        "can_we_talk",
        "i_want_to_talk",
        "talk_to_me",
        "please_talk",
    ]
    
    # Padding options
    pad_chars = ["_", "-", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]
    
    for base in bases:
        content_len = len(base)
        needed = 25 - content_len
        
        if needed >= 0:
            # Try different padding
            for pad_char in pad_chars:
                padded = base + pad_char * needed
                flag = f"CS{{{padded}}}"
                if len(flag) == 29:
                    candidates.append(flag)
        
        # Try exact length
        if content_len == 25:
            flag = f"CS{{{base}}}"
            if len(flag) == 29:
                candidates.append(flag)
    
    # Add variations with numbers
    numeric_variations = [
        "talk_to_me_please_again_1",
        "talk_to_me_please_again_2",
        "talk_to_me_please_again_3",
        "talk_to_me_please_again_00",
        "talk_to_me_please_again_01",
    ]
    
    for var in numeric_variations:
        if len(var) <= 25:
            needed = 25 - len(var)
            padded = var + "_" * needed
            flag = f"CS{{{padded}}}"
            if len(flag) == 29:
                candidates.append(flag)
    
    # Remove duplicates
    candidates = list(set(candidates))
    candidates.sort()
    
    return candidates

if __name__ == "__main__":
    candidates = generate_all_candidates()
    print(f"Generated {len(candidates)} candidates")
    print("\nFirst 20 candidates:")
    for i, cand in enumerate(candidates[:20], 1):
        print(f"  {i}. {cand}")
    
    # Save to file
    with open("flag_candidates.txt", "w") as f:
        for cand in candidates:
            f.write(cand + "\n")
    
    print(f"\nAll candidates saved to flag_candidates.txt")


