"""Debug script to test filename validation"""

filename = "VSCodeUserSetup-x64-1.109.5(1).exe"

dangerous_filename_patterns = [
    # Path traversal - CRITICAL SECURITY
    "../",
    "..\\",
    # Code injection - CRITICAL SECURITY  
    "<script",
    "</script>",
    "javascript:",
    "vbscript:",
    "data:",
    "text/html",
    # Windows reserved names - CRITICAL SECURITY
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "COM1",
    "COM2",
    "COM3",
    "COM4",
    "COM5",
    "COM6",
    "COM7",
    "COM8",
    "COM9",
    "LPT1",
    "LPT2",
    "LPT3",
    "LPT4",
    "LPT5",
    "LPT6",
    "LPT7",
    "LPT8",
    "LPT9",
]

filename_lower = filename.lower()
matched_patterns = [p for p in dangerous_filename_patterns if p in filename_lower]

print(f"Filename: {filename}")
print(f"Filename (lower): {filename_lower}")
print(f"Matched patterns: {matched_patterns}")
print(f"Would be blocked: {bool(matched_patterns)}")

# Check each pattern separately
for pattern in dangerous_filename_patterns:
    if pattern in filename_lower:
        print(f"  ❌ Matched: '{pattern}'")
