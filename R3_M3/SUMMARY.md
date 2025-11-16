# R3 M3 Challenge - Summary

## Status
- ✅ Binary downloaded and extracted
- ✅ All hash functions implemented (orbit_mist, orbit_ember, orbit_tide, orbit_quartz, orbit_haze, orbit_nova)
- ✅ Main function logic understood
- ⚠️ Flag not yet found through brute force/testing

## Key Findings

### Program Flow
1. Reads input with fgets (max 256 bytes)
2. Tests input against 5 drift_table entries:
   - XORs drift_table[i] with 0xC3B1E37F9A4D2605
   - Calls function from lanes[i]
   - Compares result
3. If no match, tests orbit_nova against 0xFCE62D194453D523

### Expected Hash Values
- expected[0]: 0x49ec606db1d2e62d
- expected[1]: 0x2ab1ab1ec269421e
- expected[2]: 0xe49a159a174cbcf8
- expected[3]: 0x47f34a499b2edd93
- expected[4]: 0x237a429b80010643
- FINAL: 0xFCE62D194453D523

### Lanes Array
- lanes[0] = 1 → likely orbit_ember
- lanes[1] = 0x200000001 → possibly orbit_tide (high 32 bits = 2)
- lanes[2] = 0 → likely orbit_mist
- lanes[3] = 0 → likely orbit_mist
- lanes[4] = 0x3050 → unknown

## Next Steps
1. Verify hash function implementations against actual binary
2. Try symbolic execution with angr
3. Test if flag format is different than expected
4. Check if hash functions have bugs (especially orbit_tide SIMD implementation)

## Files Created
- `all_hashes.py` - Complete hash function implementations
- `complete_solver.py` - Comprehensive flag search script
- `WRITEUP.md` - Detailed writeup


