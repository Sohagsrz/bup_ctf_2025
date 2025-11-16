# Dynamic Analysis Plan - Based on Search Results

## Key Finding
The kshackzone writeup for "Talk To Me" (similar challenge) suggests using **radare2** for dynamic analysis.

## Plan Based on Writeup Methodology

### Step 1: Install radare2
```bash
# macOS
brew install radare2

# Or download from: https://github.com/radareorg/radare2
```

### Step 2: Load Binary in Debug Mode
```bash
r2 -d TTMPA/ttmpa.ks
```

### Step 3: Analyze and Set Breakpoints
```bash
# Analyze all
aaa

# List functions
afl

# Go to main
s main
pdf

# Search for "nope" string
izz~nope

# Find cross-references
axt [address_of_nope]

# Set breakpoints
db [address1]
db [address2]
db [address3]
```

### Step 4: Run and Test
```bash
# Run program
dc

# When prompted, input test flag
# Analyze execution flow
# Modify input based on observations
```

### Step 5: Find Success Path
- Look for the success message: "I would like to talk to you but"
- Trace back to find what input triggers it
- Use breakpoints to understand the validation logic

## Alternative: Use Python Script with radare2
Create a script that:
1. Uses r2pipe to control radare2
2. Sets breakpoints automatically
3. Tests inputs programmatically
4. Extracts the flag when found


