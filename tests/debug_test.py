# Test different possible error message formats
error_messages = [
    'too many upload initialization requests',
    'Too many upload initialization requests', 
    'too many upload initialization requests',
    'Too many upload initialization requests'
]

for msg in error_messages:
    print(f'Message: {repr(msg)}')
    print(f'  Contains "too many upload initialization requests": {"too many upload initialization requests" in msg}')
    print(f'  Contains "Too many upload initialization requests": {"Too many upload initialization requests" in msg}')
    print()
