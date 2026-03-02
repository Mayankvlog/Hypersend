#!/usr/bin/env python3
"""Fix syntax errors and ensure proper timestamp formatting"""

# Fix syntax errors in messages.py
with open('backend/routes/messages.py', 'r') as f:
    content = f.read()

# Fix the double parenthesis and dot issues
content = content.replace('datetime.now(timezone.utc).).isoformat()', 'datetime.now(timezone.utc).isoformat()')

# Count changes
iso_count = content.count('datetime.now(timezone.utc).isoformat()')
utc_count = content.count('_utcnow().isoformat()')

with open('backend/routes/messages.py', 'w') as f:
    f.write(content)

print(f"Fixed syntax errors.")
print(f"datetime.now(timezone.utc).isoformat() calls: {iso_count}")
print(f"_utcnow().isoformat() calls: {utc_count}")
