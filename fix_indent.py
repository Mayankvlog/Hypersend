#!/usr/bin/env python3
"""Fix indentation issue in status.py"""

with open('backend/routes/status.py', 'r') as f:
    lines = f.readlines()

# Find the problematic lines and fix indentation
fixed_lines = []
i = 0
while i < len(lines):
    line = lines[i]
    # Check if this is the problematic logger.info line
    if 'logger.info(f"[STATUS_GET] get_all_statuses called for user:' in line and not line.startswith('    '):
        # This line should be indented with 4 spaces
        fixed_lines.append('    ' + line.lstrip())
    # Check if next line is the problematic try
    elif line.strip() == 'try:' and i > 0 and 'get_all_statuses' in lines[i-1] and '        try:' in line:
        # Fix over-indentation on try
        fixed_lines.append('    try:\n')
    else:
        fixed_lines.append(line)
    i += 1

with open('backend/routes/status.py', 'w') as f:
    f.writelines(fixed_lines)

print('Fixed indentation')
