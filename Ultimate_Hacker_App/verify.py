#!/usr/bin/env python3
"""
Verify the reverse function by encoding back
"""

def shuffle(input_str, lane):
    """Forward shuffle function (from Java code)"""
    if input_str is None:
        input_str = ""
    
    # Step 1: Reverse with prefix/suffix
    s = ("CSPRINT:" + input_str.strip() + ":ANDROID")[::-1]
    
    # Step 2: Case swap and digit transform
    stage4 = []
    for ch in s:
        if 'a' <= ch <= 'z':
            stage4.append(chr(ord(ch) - ord('a') + ord('A')))
        elif 'A' <= ch <= 'Z':
            stage4.append(chr(ord(ch) - ord('A') + ord('a')))
        elif '0' <= ch <= '9':
            d = ord(ch) - ord('0')
            stage4.append(chr(((d + 7) % 10) + ord('0')))
        else:
            stage4.append(ch)
    stage4_str = ''.join(stage4)
    
    # Step 3: XOR with lane
    data = stage4_str.encode('utf-8')
    keyed = bytearray(len(data))
    for i in range(len(data)):
        v = data[i] & 0xFF
        k = lane[i % len(lane)] & 255
        keyed[i] = (v ^ k) & 0xFF
    
    # Step 4: Bit rotation
    twisted = bytearray(len(keyed))
    for i in range(len(keyed)):
        v = keyed[i] & 0xFF
        if i % 2 == 0:
            twisted[i] = ((v << 1) & 255) | (v >> 7)
        else:
            twisted[i] = ((v >> 2) | ((v << 6) & 255)) & 255
    
    # Step 5: Convert to hex with separators
    out = []
    for i in range(len(twisted)):
        v = twisted[i] & 0xFF
        hex_str = format(v, '02x')
        out.append(hex_str)
        mod = i % 3
        if mod == 0:
            out.append('g')
        elif mod == 1:
            out.append('z')
        else:
            out.append('q')
    
    return ''.join(out)


# Test with the found flag
lane = [116, 162, 138, 23]
test_input = "CS{_W3lC0m3_70_AndR01d_4PP_R3_}"
encoded = shuffle(test_input, lane)
print(f"Input: {test_input}")
print(f"Encoded: {encoded}")
print(f"Expected: 20gf2zcbq59g20z33qd7g4bz12q7fg75z59q56gb4zf5q89g56zb9q65g08z0cqb9g89z9dq56g65z7dq12g88zfbq7bg1dz70qa4gfbz12q1eg74zd3q4bg00z33qc7g59z08q74gd3z")
print(f"Match: {encoded == '20gf2zcbq59g20z33qd7g4bz12q7fg75z59q56gb4zf5q89g56zb9q65g08z0cqb9g89z9dq56g65z7dq12g88zfbq7bg1dz70qa4gfbz12q1eg74zd3q4bg00z33qc7g59z08q74gd3z'}")

