#!/usr/bin/env python3
"""
Dynamic testing script - test inputs against the binary
"""

import subprocess
import sys
import os

BINARY_PATH = "TTMPA/ttmpa.ks"
SUCCESS_MSG = "I would like to talk to you but"

def test_input(test_flag, use_qemu=False):
    """Test an input against the binary"""
    try:
        # Determine command based on environment
        if use_qemu:
            cmd = ["qemu-x86_64", "-L", "/usr/x86_64-linux-gnu", BINARY_PATH]
        else:
            cmd = [BINARY_PATH]
        
        # Run the binary with the test input
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        stdout, stderr = process.communicate(input=test_flag + "\n", timeout=5)
        
        # Check for success message
        if SUCCESS_MSG in stdout:
            return True, stdout
        return False, stdout
    except FileNotFoundError:
        # Try with qemu if direct execution fails
        if not use_qemu:
            return test_input(test_flag, use_qemu=True)
        return False, "Binary not found and QEMU unavailable"
    except Exception as e:
        return False, str(e)

def generate_candidates():
    """Generate flag candidates to test"""
    candidates = []
    
    base_patterns = [
        "talk_to_me_please_again",
        "Talk_To_Me_Please_Again",
        "talktomepleaseagain",
        "please_talk_to_me",
        "the_secret_is_talk",
        "let_me_talk_to_you",
        "can_we_talk_please",
        "i_want_to_talk_now",
        "talk_please_again",
        "secret_talk_code",
    ]
    
    for pattern in base_patterns:
        content_len = len(pattern)
        needed = 25 - content_len
        
        if needed >= 0:
            for pad_char in ["_", "-", "0", "1", "2"]:
                padded = pattern + pad_char * needed
                flag = f"CS{{{padded}}}"
                if len(flag) == 29:
                    candidates.append(flag)
        
        if content_len == 25:
            flag = f"CS{{{pattern}}}"
            if len(flag) == 29:
                candidates.append(flag)
    
    # Add the hex result we found
    candidates.append("dad214f15d689aaf4ab7d7b0873d56c91036f95767a48e88664bbdf463")
    candidates.append("CS{dad214f15d689aaf4ab7d7b0873d56c91036f95767a48e88664bbdf463}")
    
    return candidates

def main():
    print("="*60)
    print("Dynamic Testing - Talk To Me Please Again")
    print("="*60)
    
    # Check if binary exists
    if not os.path.exists(BINARY_PATH):
        print(f"Error: Binary not found at {BINARY_PATH}")
        return
    
    print(f"\nTesting binary: {BINARY_PATH}")
    
    # Load candidates
    candidates = generate_candidates()
    
    # Also load from file if it exists
    if os.path.exists("flag_candidates.txt"):
        with open("flag_candidates.txt", "r") as f:
            file_candidates = [line.strip() for line in f if line.strip()]
            candidates.extend(file_candidates)
            candidates = list(set(candidates))
    
    print(f"Generated {len(candidates)} candidates to test\n")
    
    # Test each candidate
    for i, candidate in enumerate(candidates, 1):
        print(f"[{i}/{len(candidates)}] Testing: {candidate[:50]}...", end=" ", flush=True)
        success, output = test_input(candidate)
        
        if success:
            print("✅ SUCCESS!")
            print(f"\n🎉 FLAG FOUND: {candidate}")
            print(f"Output: {output}")
            with open("FOUND_FLAG.txt", "w") as f:
                f.write(candidate + "\n")
            return
        else:
            print("❌")
            if i % 10 == 0:
                print(f"  Progress: {i}/{len(candidates)} tested")
    
    print("\n" + "="*60)
    print("No flag found in generated candidates.")
    print("You may need to generate more candidates or check the binary.")

if __name__ == "__main__":
    main()


