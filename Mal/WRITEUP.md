# Mal CTF Challenge Writeup

## Challenge Information
- **Name:** Mal
- **Category:** Reverse Engineering
- **Description:** Reverse engineering challenge with obfuscation
- **Flag Format:** CS{something}
- **Binary:** mal.ks (500MB ELF 64-bit executable)

## Initial Analysis

### Binary Information
```bash
$ file mal.ks
mal.ks: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, 
interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 4.4.0, not stripped
```

- **Architecture:** 64-bit x86-64
- **Size:** 500MB (unusually large, likely padded)
- **Type:** Dynamically linked, not stripped

### Program Behavior

The program:
1. Prints: "=== Reverse Engineering Challenge ==="
2. Prompts: "Enter the flag: "
3. Reads user input
4. Hashes the input using a custom algorithm
5. Compares the hash to `0x72d59e59`
6. If correct, prints: "[+] Correct flag! Access granted. No destruction today."
7. If incorrect, prints: "[-] Incorrect flag." and may execute destructive commands

### Hash Algorithm Analysis

From disassembly of the `main` function:

```c
unsigned int hash = 0x1505;  // Initial hash value
for (char c in input_string) {
    hash = ((hash << 5) + hash + c) & 0xFFFFFFFF;
    // Equivalent to: hash = (hash * 33 + c) & 0xFFFFFFFF
}
// Compare final hash with 0x72d59e59
```

This is the **djb2 hash algorithm** (or a variant):
- Initial hash: `0x1505`
- For each character: `hash = (hash * 33 + char) mod 2^32`
- Target hash: `0x72d59e59`

### Key Strings Found

```
=== Reverse Engineering Challenge ===
Enter the flag: 
[-] Incorrect flag.
[+] Correct flag! Access granted. No destruction today.
[debug] Obfuscated marker present.
```

## Solution Approach

### Hash Reversal Challenge

Reversing a hash function is computationally difficult. The djb2 hash (`hash = hash * 33 + char`) is theoretically reversible by working backwards, but requires:

1. **Working backwards**: For each step, find the previous hash and character such that:
   - `current_hash = (prev_hash * 33 + char) mod 2^32`
   - This means: `prev_hash = (current_hash - char) / 33`
   - We need `(current_hash - char) mod 2^32` to be divisible by 33

2. **Multiple valid paths**: Due to modulo arithmetic, there may be multiple valid characters at each step, requiring exploration of all paths.

3. **Constraint**: The process must end at the initial hash value `0x1505`.

### Attempted Methods

1. **Backward iteration**: Working backwards from `0x72d59e59` to `0x1505`
2. **BFS (Breadth-First Search)**: Exploring all valid paths
3. **Modulo property**: Using `hash mod 33 = char mod 33` to constrain search
4. **Constraint solving**: Attempted with Z3 (not available in environment)

### Current Status

The hash reversal has proven computationally challenging. The flag is the input string that hashes to `0x72d59e59` starting from `0x1505`.

**Note**: The binary mentions "increased size offset style" which may be a hint about the file structure (500MB padded file), but the core challenge remains reversing the hash function.

## Tools Used

- `file` - Binary type identification
- `objdump` - Disassembly and section analysis
- `strings` - String extraction
- `hexdump` - Binary inspection
- Python scripts for hash reversal attempts

## Flag

**Status**: Pending - Hash reversal in progress

The flag is the string that produces hash `0x72d59e59` when hashed with the djb2 algorithm starting from `0x1505`.

## Next Steps

To complete this challenge:
1. Implement an efficient hash reversal algorithm
2. Use constraint solvers (Z3, etc.) if available
3. Consider if "increased size offset style" provides additional hints
4. Explore if the flag might be embedded in the binary at a specific offset

