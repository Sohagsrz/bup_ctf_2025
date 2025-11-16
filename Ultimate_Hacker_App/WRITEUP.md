# Ultimate Hacker App - CTF Writeup

**Challenge:** Ultimate Hacker App  
**Points:** 260  
**Author:** NomanProdhan  
**Flag Format:** CS{fl4g_her3}

## Challenge Description

An Android APK file that claims to be a "hacking app" from another universe. The app allows you to input a target name and simulates hacking that target.

## Initial Analysis

1. **Downloaded and extracted the challenge:**
   - Downloaded `UltimateHackerApp.zip` from Google Drive
   - Extracted using password: `aeb0d21fbedecc700dd61520a8b4c3b8`
   - Found APK file: `com.nomanprodhan.ultimatehackerapp.apk`

2. **APK Structure:**
   - Extracted the APK (APK files are ZIP archives)
   - Found multiple DEX files: `classes.dex`, `classes2.dex`, `classes3.dex`
   - No native libraries (.so files)

3. **Decompilation:**
   - Used `jadx` to decompile the APK to Java source code
   - Found main classes:
     - `MainActivity.java` - Main UI and logic
     - `Obfuscator.java` - Obfuscation/encoding logic

## Code Analysis

### MainActivity.java

The app has a simple UI where you can enter a target name. When you click "Hack", it:
1. Takes the input string
2. Calls `Obfuscator.probe(input)` to check if it matches any special signatures
3. If it matches, shows different messages for different slots (SLOT_A through SLOT_F)
4. If it doesn't match, generates random fake "hacking" output

### Obfuscator.java - The Key Logic

The `Obfuscator` class contains the obfuscation algorithm:

1. **SIGN array:** Contains 6 encoded strings (one for each slot A-F)
2. **LANES array:** Contains encryption keys (arrays of 4 integers) for each slot
3. **`probe()` method:** Checks if an input string, when encoded, matches any of the SIGN strings
4. **`shuffle()` method:** The obfuscation algorithm that encodes the input

### The Obfuscation Algorithm

The `shuffle()` function performs the following steps:

1. **String Preparation:**
   ```java
   String s = new StringBuilder("CSPRINT:" + input.trim() + ":ANDROID").reverse().toString();
   ```
   - Adds prefix "CSPRINT:" and suffix ":ANDROID"
   - Reverses the entire string

2. **Case Swap & Digit Transform:**
   - Lowercase → Uppercase
   - Uppercase → Lowercase
   - Digits: `(digit + 7) % 10`

3. **XOR Encryption:**
   - XOR each byte with a key from the `lane` array (cyclically)

4. **Bit Rotation:**
   - Even indices: Left rotate by 1 bit `((v << 1) & 255) | (v >>> 7)`
   - Odd indices: Right rotate by 2 bits `((v >>> 2) | ((v << 6) & 255)) & 255`

5. **Hex Encoding with Separators:**
   - Convert each byte to 2-digit hex
   - Insert 'g', 'z', or 'q' after every hex pair (cycling: g, z, q)

## Solution Approach

To find the flag, I needed to **reverse** the obfuscation algorithm:

1. **Extract hex bytes** from the SIGN string (remove 'g', 'z', 'q' separators)
2. **Reverse bit rotation:**
   - Even indices: Right rotate by 1 bit
   - Odd indices: Left rotate by 2 bits
3. **Reverse XOR** (XOR is its own inverse)
4. **Reverse case swap and digit transform:**
   - Case swap is its own inverse
   - Digit transform: `(d - 7) % 10`
5. **Reverse string reversal** and remove prefix/suffix

## Implementation

Created a Python script (`solve.py`) that:
- Implements the reverse of each step
- Tries all SIGN strings with all their corresponding LANES
- Finds the input that produces each SIGN

## Flag

Running the script found the flag in **SLOT_A** (first SIGN, first lane):

```
CS{_W3lC0m3_70_AndR01d_4PP_R3_}
```

### Verification

Created a verification script (`verify.py`) that:
- Takes the found flag
- Runs it through the forward obfuscation algorithm
- Confirms it matches the expected SIGN string

**Verification Result:** ✅ Match confirmed!

## Tools Used

- `jadx` - APK decompiler
- `unzip` - Extract APK contents
- Python 3 - Reverse engineering script

## Key Takeaways

1. **Android Reverse Engineering:** APK files can be decompiled to understand their logic
2. **Obfuscation Reversal:** Even complex obfuscation can be reversed step-by-step
3. **Systematic Approach:** Breaking down the algorithm into steps makes it easier to reverse
4. **Verification:** Always verify your solution by encoding it back

## Files

- `solve.py` - Main solution script that reverses the obfuscation
- `verify.py` - Verification script to confirm the flag
- `WRITEUP.md` - This writeup

---

**Flag:** `CS{_W3lC0m3_70_AndR01d_4PP_R3_}`

