#!/usr/bin/env python3
"""
Script to run production stabilization tests with proper environment
"""
import os
import sys
import subprocess

# Set required environment variables
os.environ['MONGODB_URI'] = 'mongodb+srv://mayanllr0311_db_user:JBkAZin8lytTK6vg@cluster0.rnj3vfd.mongodb.net/Hypersend?retryWrites=true&w=majority'
os.environ['DATABASE_NAME'] = 'Hypersend'
os.environ['SECRET_KEY'] = 'Prod_Secret_Key_For_Zaply_2025_Secure_Fixed'
os.environ['ENVIRONMENT'] = 'production'

# Run the tests
result = subprocess.run([
    sys.executable, '-m', 'pytest', 
    'backend/test_production_stabilization.py', '-v'
], capture_output=True, text=True)

print("STDOUT:")
print(result.stdout)
print("\nSTDERR:")
print(result.stderr)
print(f"\nReturn code: {result.returncode}")
