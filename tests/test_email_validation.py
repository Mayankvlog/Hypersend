#!/usr/bin/env python3
"""
Test email validation error types
"""

from pydantic import ValidationError
from pydantic import EmailStr

# Test email validation
try:
    EmailStr('invalid-email-format')
except ValidationError as e:
    print('ValidationError errors:')
    for error in e.errors():
        print(f'  Type: {error.get("type")}, Field: {error.get("loc")}')
