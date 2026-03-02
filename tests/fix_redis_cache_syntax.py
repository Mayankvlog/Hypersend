#!/usr/bin/env python3
"""Fix malformed datetime expressions in redis_cache.py"""

file_path = "backend/redis_cache.py"

with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

# Fix pattern 1: datetime.now(timezone.utc).).isoformat()
# Replace with: datetime.now(timezone.utc).isoformat()
original_count_1 = content.count("datetime.now(timezone.utc).).isoformat()")
content = content.replace(
    "datetime.now(timezone.utc).).isoformat()",
    "datetime.now(timezone.utc).isoformat()"
)

# Fix pattern 2: datetime.now(timezone.utc).) + timedelta
# Replace with: datetime.now(timezone.utc) + timedelta
original_count_2 = content.count("datetime.now(timezone.utc).) +")
content = content.replace(
    "datetime.now(timezone.utc).) +",
    "datetime.now(timezone.utc) +"
)

# Fix pattern 3: datetime.now(timezone.utc).) >=
# Replace with: datetime.now(timezone.utc) >=
original_count_3 = content.count("datetime.now(timezone.utc).) >=")
content = content.replace(
    "datetime.now(timezone.utc).) >=",
    "datetime.now(timezone.utc) >="
)

# Fix pattern 4: (datetime.now(timezone.utc).) + - malformed in assignment
# Need to handle: "next_retry": ( datetime.now(timezone.utc).) + timedelta(...) ).isoformat()
original_count_4 = content.count("(datetime.now(timezone.utc).) +")
if original_count_4 > 0:
    # More complex fix - need to handle the full expression
    import re
    # Pattern: ( datetime.now(timezone.utc).) + timedelta(...) ).isoformat()
    pattern = r"\(datetime\.now\(timezone\.utc\)\.\) \+"
    replacement = "(datetime.now(timezone.utc) +"
    content = re.sub(pattern, replacement, content)

with open(file_path, 'w', encoding='utf-8') as f:
    f.write(content)

print(f"✓ Fixed {original_count_1} occurrences of datetime.now(timezone.utc).).isoformat()")
print(f"✓ Fixed {original_count_2} occurrences of datetime.now(timezone.utc).) +")
print(f"✓ Fixed {original_count_3} occurrences of datetime.now(timezone.utc).) >=")
print(f"✓ Fixed {original_count_4} occurrences of (datetime.now(timezone.utc).) +")
print("✓ All datetime syntax errors fixed!")
