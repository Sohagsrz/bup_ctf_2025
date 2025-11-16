# BUP CTF 2025 - Challenge Solutions

This repository contains solutions and writeups for various CTF challenges from BUP CTF 2025.

## 📋 Table of Contents

- [Challenges](#challenges)
- [Setup](#setup)
- [Challenges Overview](#challenges-overview)
- [Solutions](#solutions)

## 🎯 Challenges

| Challenge | Category | Points | Status | Flag |
|-----------|----------|--------|--------|------|
| [CIA](#cia) | Web | 500 | ✅ Solved | `CS{a711525257ac064525eb620f4e224e8e}` |
| [vCIA](#vcia) | Web | 500 | ✅ Solved | See writeup |
| [Mal](#mal) | Reverse Engineering | 500 | ✅ Solved | `CS{PYwZ:2}` |
| [R3_M3](#r3_m3) | Reverse Engineering | - | 🔄 In Progress | - |
| [Red Dragon Syndicate](#red-dragon-syndicate) | Binary Exploitation | 500 | ✅ Solved | `CS{vicious_red_dragon_syndicate_6919506bb161ee2b068f825f}` |
| [Ultimate Hacker App](#ultimate-hacker-app) | Mobile/Reverse | 260 | ✅ Solved | `CS{_W3lC0m3_70_AndR01d_4PP_R3_}` |
| [Shadow of a Knight](#shadow-of-a-knight) | Forensics/Network | - | 🔄 In Progress | - |
| [Talk To Me Please Again](#talk-to-me-please-again) | Reverse Engineering | - | 🔄 In Progress | - |

## 🚀 Setup

### Prerequisites

- Python 3.8+
- Node.js (for web challenges)
- Common reverse engineering tools (objdump, strings, etc.)

### Python Dependencies

For challenges requiring Z3 solver:
```bash
cd Mal
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install z3-solver
```

### Node.js Dependencies

For web challenges:
```bash
cd CIA  # or vCIA
npm install
```

## 📖 Challenges Overview

### CIA

**Category:** Web  
**Points:** 500  
**Author:** badhacker0x01

A web challenge involving bypassing server-side validation using BOM (Byte Order Mark) characters in JSON requests.

**Key Techniques:**
- BOM (Byte Order Mark) injection
- JSON parsing bypass
- Server-side validation evasion

**Flag:** `CS{a711525257ac064525eb620f4e224e8e}`

📝 [Full Writeup](CIA/WRITEUP.md)

---

### vCIA

**Category:** Web  
**Points:** 500  
**Author:** badhacker0x01

Similar to CIA challenge but with different validation mechanisms.

📝 [Full Writeup](vCIA/WRITEUP.md)

---

### Mal

**Category:** Reverse Engineering  
**Points:** 500  
**Author:** NomanProdhan

A reverse engineering challenge requiring hash function reversal. The binary uses a djb2-like hash algorithm and checks if the input hashes to a specific target value.

**Key Techniques:**
- Hash function reverse engineering
- Z3 constraint solving
- Binary analysis

**Hash Algorithm:**
```python
hash = 0x1505
for char in input:
    hash = ((hash << 5) + hash + ord(char)) & 0xFFFFFFFF
# Target hash: 0x72d59e59
```

**Flag:** `CS{PYwZ:2}`

📝 [Full Writeup](Mal/WRITEUP.md)

---

### R3_M3

**Category:** Reverse Engineering  
**Points:** -  
**Author:** -

A reverse engineering challenge involving multiple hash functions and path finding.

📝 [Full Writeup](R3_M3/WRITEUP.md)

---

### Red Dragon Syndicate

**Category:** Binary Exploitation / Pwn  
**Points:** 500  
**Author:** froghunter

A classic buffer overflow challenge with executable stack. Can be solved using ROP or shellcode injection.

**Key Techniques:**
- Buffer overflow exploitation
- ROP (Return-Oriented Programming)
- Address leaking
- Function pointer manipulation

**Flag:** `CS{vicious_red_dragon_syndicate_6919506bb161ee2b068f825f}`

📝 [Full Writeup](Red_Dragon_Syndicate/WRITEUP.md)

---

### Ultimate Hacker App

**Category:** Mobile / Reverse Engineering  
**Points:** 260  
**Author:** NomanProdhan

An Android APK reverse engineering challenge. The app contains obfuscated flag data that needs to be decoded.

**Key Techniques:**
- APK reverse engineering
- DEX file analysis
- Obfuscation algorithm reversal
- Android app decompilation

**Flag:** `CS{_W3lC0m3_70_AndR01d_4PP_R3_}`

📝 [Full Writeup](Ultimate_Hacker_App/WRITEUP.md)

---

### Shadow of a Knight

**Category:** Forensics / Network  
**Points:** -  
**Author:** -

A network forensics challenge involving packet capture analysis and decryption.

📝 [Full Writeup](Shadow_of_a_Knight/) - In Progress

---

### Talk To Me Please Again

**Category:** Reverse Engineering  
**Points:** -  
**Author:** -

A reverse engineering challenge requiring dynamic analysis.

📝 [Full Writeup](Talk_To_Me_Please_Again/WRITEUP.md) - In Progress

---

## 🛠️ Solutions

Each challenge folder contains:
- `WRITEUP.md` - Detailed solution writeup
- Solution scripts (Python, JavaScript, etc.)
- Analysis tools and scripts
- Challenge files (where applicable)

### Quick Solution Access

```bash
# Web challenges
cd CIA && node solve_final.js
cd vCIA && node solve_final.js

# Reverse engineering
cd Mal && python3 fast_solve.py
cd R3_M3 && python3 solve.py

# Binary exploitation
cd Red_Dragon_Syndicate && python3 exploit_rop.py

# Mobile
cd Ultimate_Hacker_App && python3 solve.py
```

## 📝 Notes

- Large binary files (`.ks`, `.zip`, `.apk`) are excluded from git
- Virtual environments are excluded from git
- Each challenge has its own detailed writeup with step-by-step solutions
- Some challenges may have multiple solution approaches documented

## 🔒 Important

**⚠️ WARNING:** Some challenges (especially Mal) contain destructive code. Only run binaries in isolated sandboxes or disposable virtual machines.

## 📚 Learning Resources

- [Z3 Solver Documentation](https://github.com/Z3Prover/z3)
- [CTF Writeups Best Practices](https://github.com/CTF-Archives)
- [Reverse Engineering Tools](https://github.com/radareorg/radare2)

## 🤝 Contributing

If you find improvements or alternative solutions, feel free to:
1. Document them in the respective writeup
2. Add alternative solution scripts
3. Improve code comments and documentation

## 📄 License

This repository is for educational purposes only. All challenges and solutions are from BUP CTF 2025.

---

**Happy Hacking! 🚀**
