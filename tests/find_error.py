import os
for root, dirs, files in os.walk('backend'):
    for file in files:
        if file.endswith('.py'):
            path = os.path.join(root, file)
            try:
                with open(path, encoding='utf-8', errors='ignore') as f:
                    for i, line in enumerate(f, 1):
                        if 'Dangerous filename detected' in line:
                            print(f"{path}:{i}: {line.strip()}")
            except:
                pass
