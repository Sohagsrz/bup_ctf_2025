#!/usr/bin/env python3
"""
Dynamic analysis using radare2 via r2pipe
"""

try:
    import r2pipe
    R2_AVAILABLE = True
except ImportError:
    R2_AVAILABLE = False
    print("r2pipe not available. Install with: pip install r2pipe")

BINARY_PATH = "TTMPA/ttmpa.ks"

def analyze_with_r2():
    """Use radare2 to dynamically analyze the binary"""
    if not R2_AVAILABLE:
        print("r2pipe not available")
        return None
    
    try:
        # Open binary in radare2
        r2 = r2pipe.open(BINARY_PATH)
        
        # Analyze
        r2.cmd("aaa")
        
        # Find main function
        main_info = r2.cmd("pdf @ main")
        print("Main function:")
        print(main_info[:500])
        
        # Search for strings
        strings = r2.cmd("izz")
        print("\nStrings found:")
        for line in strings.split('\n')[:20]:
            if 'nope' in line.lower() or 'talk' in line.lower():
                print(f"  {line}")
        
        # Find bucket_root
        bucket_info = r2.cmd("px 29 @ bucket_root")
        print("\nBucket_root data:")
        print(bucket_info)
        
        r2.quit()
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    if R2_AVAILABLE:
        analyze_with_r2()
    else:
        print("To use this script:")
        print("1. Install radare2: brew install radare2")
        print("2. Install r2pipe: pip install r2pipe")
        print("3. Run this script again")


