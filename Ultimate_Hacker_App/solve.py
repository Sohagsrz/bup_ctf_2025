#!/usr/bin/env python3
"""
Reverse the obfuscation algorithm to find the flag
"""

# The SIGN strings from Obfuscator.java
SIGN = [
    "20gf2zcbq59g20z33qd7g4bz12q7fg75z59q56gb4zf5q89g56zb9q65g08z0cqb9g89z9dq56g65z7dq12g88zfbq7bg1dz70qa4gfbz12q1eg74zd3q4bg00z33qc7g59z08q74gd3z",
    "84g7az8fq52g84zbbq93g40zb6qacg23z03q3egf7zf7q9cgeaz76qc9g82zd0q70gefz1eq3cg73z33q5dgfez31qefgdfz3cqedgf5zdfqd0g70za7q57ga4zf8qdbgddzc2qf3gcfz17q38g3dz8dq94ga8z3cqb7g16z",
    "52g43z98qa3g52z82q84gb1z60q95g34zf2qe8gcezccqebg3ez48qeag6ez3eqcegcezafq24g0czdaq6dg3ez0dqe0ge8z3eq48gd6z2bq08gc9zb0qe7g50zc5q8ega7zeeq04g9az65q7eg05za0qe7g",
    "87g5ez38q65g87z9fq24g77zb5q88g94z34q3dgd3z7aq2agddzd0q40ga8ze9qd3g6cz2dqebg55z4aqa8gebzd3q62ga9zd7qd3g6czeaqddg94z78qaagb9z18q0cg61z3bq19g3aza3qabg18z00q21g",
    "10gfazfdqd1g10z3bqe1gc3z22qadg43z41qa8g77za9q5eg4az30qbdg1ez66q72ga5z1dq7cgb5z9dq1cg7ez34qa9gd8z52q34g9dz99q5eg7ezefq50g1ez7aq57g50z04qfagc7z51q3eg78z",
    "bbg84z35qb5gbbz45q29ga7z89q8fg6dz7bqdbg0ez69qbdgd3z09q65gbaze1qcdg65zbaqf1g8dz55qf8gefz8cq4fg3czd5q09g63z7bqedg4az63qbagf1z00q65g79zebq4fg9fz34qafg84z0fq35g95z06q"
]

# The LANES from Obfuscator.java
LANES = [
    [[116, 162, 138, 23], [174, 103, 71, 195], [177, 206, 232, 103], [79, 244, 157, 218], [2, 94, 101, 13], [227, 214, 51, 218], [73, 193, 84, 255], [227, 120, 196, 5], [1, 70, 115, 231], [184, 47, 22, 191]],
    [[38, 128, 168, 59], [211, 113, 251, 48], [71, 11, 183, 15], [193, 131, 1, 58], [12, 39, 170, 94], [81, 152, 181, 82], [234, 72, 13, 119], [63, 63, 163, 147], [20, 251, 183, 11], [241, 135, 182, 181]],
    [[77, 100, 35, 252], [8, 137, 218, 208], [7, 172, 100, 250], [254, 91, 154, 120], [117, 37, 30, 39], [162, 216, 69, 71], [26, 245, 6, 95], [9, 169, 23, 41], [140, 246, 187, 8], [254, 17, 70, 157]],
    [[167, 16, 115, 231], [223, 253, 195, 174], [165, 187, 123, 17], [188, 173, 86, 84], [198, 70, 25, 209], [105, 147, 128, 152], [224, 150, 46, 137], [236, 209, 184, 178], [161, 30, 105, 231], [134, 188, 238, 122]],
    [[1, 130, 145, 53], [248, 191, 27, 128], [199, 134, 242, 157], [139, 101, 40, 131], [201, 130, 244, 140], [53, 45, 215, 20], [253, 214, 157, 209], [8, 175, 214, 217], [229, 3, 105, 56], [13, 193, 41, 199]],
    [[185, 123, 245, 164], [229, 244, 51, 231], [39, 211, 122, 158], [223, 166, 107, 224], [57, 143, 126, 0], [254, 49, 222, 164], [46, 206, 39, 67], [95, 132, 219, 175], [30, 193, 152, 42], [86, 28, 240, 138]]
]


def decode_hex_string(encoded_str):
    """Extract hex bytes from the encoded string (remove 'g', 'z', 'q' separators)"""
    # Remove all 'g', 'z', 'q' characters
    hex_str = encoded_str.replace('g', '').replace('z', '').replace('q', '')
    # Convert hex string to bytes
    bytes_list = []
    for i in range(0, len(hex_str), 2):
        if i + 1 < len(hex_str):
            bytes_list.append(int(hex_str[i:i+2], 16))
    return bytes(bytes_list)


def reverse_twist(twisted):
    """Reverse the bit rotation step"""
    untwisted = bytearray(len(twisted))
    for i in range(len(twisted)):
        v = twisted[i] & 0xFF
        if i % 2 == 0:
            # Reverse: ((v << 1) & 255) | (v >>> 7)
            # Original was: v = ((v << 1) & 255) | (v >>> 7)
            # Reverse: ((v >>> 1) | ((v << 7) & 255)) & 255
            untwisted[i] = ((v >> 1) | ((v << 7) & 255)) & 255
        else:
            # Reverse: ((v >>> 2) | ((v << 6) & 255)) & 255
            # Original was: v = ((v >>> 2) | ((v << 6) & 255)) & 255
            # Reverse: ((v << 2) & 255) | (v >> 6)
            untwisted[i] = ((v << 2) & 255) | (v >> 6)
    return bytes(untwisted)


def reverse_xor(keyed, lane):
    """Reverse the XOR step"""
    data = bytearray(len(keyed))
    for i in range(len(keyed)):
        v = keyed[i] & 0xFF
        k = lane[i % len(lane)] & 255
        data[i] = (v ^ k) & 0xFF
    return bytes(data)


def reverse_case_swap_and_digit_transform(stage4_str):
    """Reverse the case swap and digit transformation"""
    result = []
    for ch in stage4_str:
        if ch >= 'a' and ch <= 'z':
            result.append(chr(ord(ch) - ord('a') + ord('A')))
        elif ch >= 'A' and ch <= 'Z':
            result.append(chr(ord(ch) - ord('A') + ord('a')))
        elif ch >= '0' and ch <= '9':
            d = ord(ch) - ord('0')
            # Reverse: (d + 7) % 10
            # We need: original_d such that (original_d + 7) % 10 = d
            # original_d = (d - 7) % 10
            original_d = (d - 7) % 10
            result.append(chr(original_d + ord('0')))
        else:
            result.append(ch)
    return ''.join(result)


def reverse_shuffle(encoded_str, lane):
    """Reverse the entire shuffle process"""
    # Step 1: Extract hex bytes
    twisted = decode_hex_string(encoded_str)
    
    # Step 2: Reverse bit rotation
    keyed = reverse_twist(twisted)
    
    # Step 3: Reverse XOR
    data = reverse_xor(keyed, lane)
    
    # Step 4: Convert bytes to string
    stage4_str = data.decode('utf-8', errors='ignore')
    
    # Step 5: Reverse case swap and digit transform
    stage3_str = reverse_case_swap_and_digit_transform(stage4_str)
    
    # Step 6: Reverse the string reversal and remove prefix/suffix
    # Original: "CSPRINT:" + input.trim() + ":ANDROID" was reversed
    # So we reverse it back
    reversed_str = stage3_str[::-1]
    
    # Remove "CSPRINT:" prefix and ":ANDROID" suffix
    if reversed_str.startswith("CSPRINT:") and reversed_str.endswith(":ANDROID"):
        original_input = reversed_str[8:-8]  # Remove "CSPRINT:" (8 chars) and ":ANDROID" (8 chars)
        return original_input
    
    return None


def find_flag():
    """Try to reverse each SIGN to find the flag"""
    slot_names = ['SLOT_A', 'SLOT_B', 'SLOT_C', 'SLOT_D', 'SLOT_E', 'SLOT_F']
    
    for idx, sign in enumerate(SIGN):
        print(f"\n=== Trying {slot_names[idx]} ===")
        for lane_idx, lane in enumerate(LANES[idx]):
            try:
                result = reverse_shuffle(sign, lane)
                if result:
                    print(f"Lane {lane_idx}: Found input: '{result}'")
                    # Check if it looks like a flag
                    if 'CS{' in result or 'flag' in result.lower():
                        print(f"*** POTENTIAL FLAG: {result} ***")
                        return result
            except Exception as e:
                pass
    
    return None


if __name__ == "__main__":
    print("Reversing obfuscation to find the flag...")
    flag = find_flag()
    if flag:
        print(f"\n🎉 FLAG FOUND: {flag}")
    else:
        print("\n❌ Flag not found. Trying all combinations...")
        # Try all combinations
        for idx, sign in enumerate(SIGN):
            for lane_idx, lane in enumerate(LANES[idx]):
                try:
                    result = reverse_shuffle(sign, lane)
                    if result:
                        print(f"SIGN[{idx}], Lane[{lane_idx}]: {result}")
                except:
                    pass

