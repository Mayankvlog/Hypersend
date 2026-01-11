#!/usr/bin/env python3
"""
Check the current user password in MongoDB
"""
import asyncio
import sys
import os
from pathlib import Path

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

def redact_email(email: str, min_length: int = 15) -> str:
    """
    Redact email address to protect PII.
    
    Keeps the first character of local-part and full domain,
    masks the rest of the local-part with asterisks.
    
    Args:
        email: Email address to redact
        min_length: Minimum email length before redacting (default 15, not enforced)
    
    Returns:
        Redacted email or placeholder if invalid
    """
    if not email or not isinstance(email, str):
        return '[REDACTED]'
    
    if '@' not in email:
        return '[REDACTED]'
    
    # Split local part and domain
    local_part, domain = email.split('@', 1)
    
    # Keep first char of local part, mask the rest
    if len(local_part) <= 1:
        masked_local = local_part
    else:
        masked_local = local_part[0] + '*' * (len(local_part) - 1)
    
    return f"{masked_local}@{domain}"

async def check_user():
    from backend.config import settings
    from motor.motor_asyncio import AsyncIOMotorClient
    
    # Get test email from environment or use a test default
    test_email = os.getenv("TEST_USER_EMAIL", "test@example.com")
    
    # Connect to MongoDB
    client = AsyncIOMotorClient(
        settings.MONGODB_URI,
        serverSelectionTimeoutMS=10000,
        connectTimeoutMS=10000,
        socketTimeoutMS=30000,
        retryWrites=False,
        maxPoolSize=10,
        minPoolSize=2
    )
    
    try:
        # Ping to check connection
        result = await client.admin.command('ping')
        print(f"[OK] Connected to MongoDB: {result}")
        
        # Get database
        db = client[settings._MONGO_DB]
        
        # Find the user
        users_col = db['users']
        user = await users_col.find_one({"email": test_email})
        
        if user:
            email = user.get('email', '[REDACTED]')
            # Redact email to protect PII
            email_redacted = redact_email(email)
            print(f"\n[FOUND] User: {email_redacted}")
            print(f"  ID: {user.get('_id')}")
            print(f"  Password Hash: [REDACTED] (length: {len(user.get('password_hash', ''))})")
            print(f"  Password Salt: {'Present' if user.get('password_salt') else 'Missing'}")
            if user.get('password_salt'):
                print(f"    Length: {len(user.get('password_salt', ''))}")
            print(f"  Has legacy 'password' field: {'Yes' if 'password' in user else 'No'}")
        else:
            print("[NOT FOUND] User not found in MongoDB")
            
            # List all users to see what's there - with bounded sample
            all_users = await users_col.find({}).to_list(length=10)  # Limit to 10 users
            print(f"\nFirst {len(all_users)} users in database:")
            for u in all_users:
                email = u.get('email', '[REDACTED]')
                # Redact the email using helper function
                email_redacted = redact_email(email)
                print(f"  - {email_redacted}: hash_len={len(u.get('password_hash', ''))}, salt={'Yes' if u.get('password_salt') else 'No'}")
                
    finally:
        client.close()

if __name__ == "__main__":
    asyncio.run(check_user())
