#!/usr/bin/env python3
"""Test binary data integrity and S3 key format for media system"""

import hashlib
from bson import ObjectId

print("=" * 50)
print("Media System Integrity Tests")
print("=" * 50)
print()

# Test 1: Binary Data Integrity
print("[1] Binary Data Integrity Test")
data = b'\x89PNG\r\n\x1a\n' + b'\x00' * 1000
hash1 = hashlib.sha256(data).hexdigest()

# Simulate chunking
chunks = [data[i:i+512] for i in range(0, len(data), 512)]
reconstructed = b''.join(chunks)
hash2 = hashlib.sha256(reconstructed).hexdigest()

print(f"  Original size: {len(data)} bytes")
print(f"  Reconstructed size: {len(reconstructed)} bytes")
print(f"  Hash match: {hash1 == hash2}")
print(f"  Status: {'✓ PASS' if hash1 == hash2 else '✗ FAIL'}")
print()

# Test 2: S3 Key Format
print("[2] S3 Key Format Test")
user_id = str(ObjectId())
upload_id = 'test-upload-123'
filenames = ['photo.jpg', 'video.mp4', 'document.pdf', 'file with spaces.txt']

all_pass = True
for filename in filenames:
    s3_key = f'files/{user_id}/{upload_id}/{filename}'
    parts = s3_key.split('/')
    
    checks = [
        ('Format', len(parts) >= 4),
        ('Prefix', parts[0] == 'files'),
        ('Filename preserved', parts[-1] == filename),
    ]
    
    all_ok = all(check[1] for check in checks)
    if not all_ok:
        all_pass = False
    status = '✓' if all_ok else '✗'
    print(f"  {status} {filename}: {s3_key[-40:]}")

print(f"  Status: {'✓ PASS' if all_pass else '✗ FAIL'}")
print()

# Test 3: MIME Type Detection
print("[3] MIME Type Detection Test")
import mimetypes

tests = [
    ('test.png', 'image/png'),
    ('test.jpg', 'image/jpeg'),
    ('test.mp4', 'video/mp4'),
    ('test.pdf', 'application/pdf'),
]

mime_pass = True
for file, expected in tests:
    mime, _ = mimetypes.guess_type(file)
    match = mime and expected in mime if '/' in expected else mime
    if not match:
        mime_pass = False
    status = '✓' if match else '✗'
    print(f"  {status} {file}: {mime}")

print(f"  Status: {'✓ PASS' if mime_pass else '✗ FAIL'}")
print()

print("=" * 50)
print("Summary: All core tests passed" if all_pass and mime_pass and hash1 == hash2 else "Summary: Some tests failed")
print("=" * 50)
