#!/usr/bin/env python3
"""
Test email validation error types
"""

from pydantic import BaseModel, ValidationError, EmailStr

class TestModel(BaseModel):
    email: EmailStr

# Test email validation
try:
    TestModel(email='invalid-email-format')
except ValidationError as e:
    print('ValidationError errors:')
    for error in e.errors():
        print(f'  Type: {error.get("type")}, Field: {error.get("loc")}')
