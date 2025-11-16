# R3 M3 - CTF Writeup

**Challenge:** R3 M3  
**Points:** 500  
**Category:** Reverse Engineering  
**Author:** NomanProdhan  
**Flag Format:** CS{something_her3}

## Challenge Description

Time to reverse a binary! The challenge provides a zip file containing a binary that needs to be reverse engineered to find the flag.

## Initial Analysis

### File Extraction

1. Downloaded `r3M3.zip` from Google Drive
2. Extracted using password: `aeb0d21fbedecc700dd61520a8b4c3b8`
3. Found binary: `reMe/reMe.ks` (524MB ELF 64-bit binary)

### Binary Analysis

The binary is a large ELF file (500MB) that appears to be mostly null bytes, with the actual code at the beginning.

**Key Findings:**
- ELF 64-bit LSB pie executable
- Dynamically linked
- Not stripped (symbols present)
- Functions: `orbit_mist`, `orbit_ember`, `orbit_tide`, `orbit_quartz`, `orbit_haze`, `orbit_nova`

## Program Logic

### Main Function Flow

1. Reads input using `fgets()` (max 256 bytes)
2. Removes newline/carriage return characters
3. Loops through 5 entries in `drift_table`:
   - XORs each entry with key `0xC3B1E37F9A4D2605`
   - Calls a function from `lanes` array with (input, strlen)
   - Compares result with XORed drift_table value
   - If match found, prints "Congrats, you did good reverse :P"
4. If no match, calls `orbit_nova(input, strlen)`
   - Compares result with `0xFCE62D194453D523`
   - If match, prints "Congrats, you did good reverse :D"
5. Otherwise prints "Nope :("

### Data Structures

**Drift Table (at offset 0x2060):**
```
[0] = 0x8a5d83122b9fc028
[1] = 0xe90048615824641b
[2] = 0x272bf6e58d019afd
[3] = 0x8442a9360163fb96
[4] = 0xe0cba1e41a4c2046
```

**XOR Key:** `0xC3B1E37F9A4D2605`

**Expected Hashes (after XOR):**
```
[0] = 0x49ec606db1d2e62d
[1] = 0x2ab1ab1ec269421e
[2] = 0xe49a159a174cbcf8
[3] = 0x47f34a499b2edd93
[4] = 0x237a429b80010643
```

**Final Check Value:** `0xFCE62D194453D523`

**Lanes Array (at offset 0x3da0):**
- Structure unclear - appears to contain function pointers or indices
- Values: `[0x1, 0x200000001, 0x0, 0x0, 0x3050]`
- When interpreted as 32-bit: `[1, 0, 1, 2, 0, 0, 0, 0, 0x3050, 0]`

### Hash Functions

The binary implements 6 hash functions:

1. **orbit_mist** (0x1300): Complex hash with rotations and multiplications
2. **orbit_ember** (0x13b0): Processes input in reverse pairs
3. **orbit_tide** (0x1470): Uses SIMD instructions for fast hashing
4. **orbit_quartz** (0x1620): Another complex hash function
5. **orbit_haze** (0x1710): Uses XOR key `0xC3B1E37F9A4D2605`
6. **orbit_nova** (0x17d0): Final check function

## Solution Approach

### Method 1: Reverse Hash Functions

The challenge requires finding inputs that hash to specific values. This is a classic hash reversal problem.

**Steps:**
1. Implement all hash functions correctly
2. Determine the mapping between lanes array and hash functions
3. For each expected hash, find an input that produces it
4. Combine inputs or find a single input that satisfies all conditions

**Challenges:**
- Hash functions are one-way (designed to be irreversible)
- Multiple hash functions need to be reversed
- The lanes array mapping is unclear

### Method 2: Symbolic Execution

Use tools like angr or z3 to symbolically execute the binary and solve for the input.

**Tools:**
- `angr`: Python framework for symbolic execution
- `z3`: SMT solver for constraint solving

### Method 3: Brute Force (Limited)

For short inputs, brute force might be feasible:
- Try common flag formats: `CS{...}`
- Try common words and patterns
- Limited to short inputs due to exponential complexity

## Implementation Status

### Completed
- ✅ Binary extraction and analysis
- ✅ Identified main program logic
- ✅ Extracted data structures (drift_table, lanes, constants)
- ✅ Partial implementation of `orbit_mist` and `orbit_ember`
- ✅ Identified all hash functions

### Remaining Work
- ⏳ Complete implementation of all hash functions
- ⏳ Determine lanes array function mapping
- ⏳ Reverse hash functions to find inputs
- ⏳ Verify solution with the binary

## Files Created

- `analyze.py`: Extracts key data structures from binary
- `solve.py`: Initial solver framework
- `implement_hashes.py`: Hash function implementations
- `analyze_lanes.py`: Analysis of lanes array structure

## Next Steps

1. **Complete hash function implementations:**
   - Finish `orbit_tide`, `orbit_quartz`, `orbit_haze`, `orbit_nova`
   - Test implementations match binary behavior

2. **Determine lanes mapping:**
   - Analyze binary structure more carefully
   - Check for function tables or jump tables
   - Test different interpretations

3. **Solve for inputs:**
   - Use symbolic execution (angr/z3)
   - Or implement hash reversal algorithms
   - Or brute force with constraints

4. **Verify solution:**
   - Run binary with found input
   - Confirm flag format matches `CS{...}`

## Notes

- The binary is 500MB but mostly null bytes - actual code is small
- Hash functions are complex and non-linear, making reversal difficult
- The lanes array structure is ambiguous and needs further analysis
- This challenge likely requires advanced reverse engineering techniques

## Progress Made

### Completed Analysis
1. ✅ Extracted and analyzed the binary structure
2. ✅ Identified all 6 hash functions (orbit_mist, orbit_ember, orbit_tide, orbit_quartz, orbit_haze, orbit_nova)
3. ✅ Extracted drift_table, XOR key, and expected hash values
4. ✅ Implemented orbit_mist and orbit_ember hash functions
5. ✅ Implemented orbit_nova hash function (partial)
6. ✅ Identified function table in binary
7. ✅ Analyzed lanes array structure
8. ✅ Set up angr for symbolic execution
9. ✅ Tested multiple flag candidates

### Key Findings
- **Drift Table**: 5 entries that get XORed with `0xC3B1E37F9A4D2605`
- **Expected Hashes**: 
  - `0x49ec606db1d2e62d`
  - `0x2ab1ab1ec269421e`
  - `0xe49a159a174cbcf8`
  - `0x47f34a499b2edd93`
  - `0x237a429b80010643`
- **Final Check**: `0xFCE62D194453D523` (for orbit_nova)
- **Lanes Array**: Contains function indices/pointers (mapping still unclear)
  - `lanes[0] = 0x1` → likely orbit_ember (index 1)
  - `lanes[2/3] = 0x0` → likely orbit_mist (index 0)

### Remaining Work
1. ⏳ Complete implementation of orbit_tide, orbit_quartz, orbit_haze
2. ⏳ Determine exact lanes array mapping to hash functions
3. ⏳ Find input that produces expected hash values
4. ⏳ Verify solution with the binary

## Solution Approaches Tried

1. **Direct Hash Testing**: Tested common flag patterns with implemented hash functions
2. **Brute Force**: Attempted brute force for short flags (limited by search space)
3. **Symbolic Execution**: Set up angr but execution is slow for this complex binary
4. **Pattern Matching**: Tested variations of hint "something_her3"

## Next Steps to Complete

1. **Complete Hash Implementations**:
   - Finish orbit_tide (uses SIMD instructions)
   - Finish orbit_quartz
   - Finish orbit_haze

2. **Determine Lanes Mapping**:
   - The lanes array likely maps to hash functions
   - Need to understand how `lanes[1] = 0x200000001` is interpreted
   - May need to test all combinations

3. **Find the Flag**:
   - Once all hash functions are implemented, test systematically
   - Use constraint solver (z3) to solve for inputs
   - Or use angr with better constraints and patience

4. **Alternative Approaches**:
   - Check if flag is derivable from hash values
   - Look for patterns in the binary
   - Try running binary in Linux environment (qemu/docker)

## Conclusion

This is a complex reverse engineering challenge involving multiple hash functions. Significant progress has been made in:
- Binary analysis and structure understanding
- Hash function implementation (partial)
- Setting up tools for solving

The challenge requires completing the hash function implementations and either:
- Systematic testing of all possible inputs
- Advanced symbolic execution with proper constraints
- Or finding the correct interpretation of the lanes array

The flag format is `CS{something_her3}` and the challenge name is "R3 M3", suggesting the flag might be related to these hints.

