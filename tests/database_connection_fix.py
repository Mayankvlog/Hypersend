#!/usr/bin/env python3
"""
Database connection fix for Hypersend
Ensures both upload and download use the same database connection
"""

import os
import sys
from dotenv import load_dotenv

# Add backend to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

def fix_database_connection():
    """Fix database connection to ensure consistency"""
    print("🔧 DATABASE CONNECTION FIX")
    print("=" * 50)
    
    try:
        # Load environment variables from .env file
        env_path = os.path.join(os.path.dirname(__file__), 'backend', '.env')
        load_dotenv(env_path)
        
        # Check current environment
        mongodb_uri = os.getenv("MONGODB_URI")
        database_name = os.getenv("DATABASE_NAME")
        
        print(f"🔍 Current MONGODB_URI: {mongodb_uri[:50]}..." if mongodb_uri else "❌ MONGODB_URI not set")
        print(f"🔍 Current DATABASE_NAME: {database_name}" if database_name else "❌ DATABASE_NAME not set")
        
        # The issue is that we removed the database name from URI
        # But the database connection might still be inconsistent
        # Let's ensure the URI includes the database name for consistency
        
        if mongodb_uri and database_name:
            if not mongodb_uri.endswith(f"/{database_name}"):
                # Add database name to URI for consistency
                if "?" in mongodb_uri:
                    # URI has query parameters, add database before them
                    base_uri = mongodb_uri.split("?")[0]
                    query_params = mongodb_uri.split("?")[1]
                    new_uri = f"{base_uri}/{database_name}?{query_params}"
                else:
                    # No query parameters, just add database
                    new_uri = f"{mongodb_uri}/{database_name}"
                
                print(f"🔧 Fixing MONGODB_URI to include database name")
                print(f"🔧 New URI: {new_uri[:50]}...")
                
                # Update environment variable
                os.environ["MONGODB_URI"] = new_uri
                
                # Update the .env file
                env_content = None
                with open(env_path, 'r') as f:
                    env_content = f.read()
                
                # Replace the MONGODB_URI line
                lines = env_content.split('\n')
                for i, line in enumerate(lines):
                    if line.startswith('MONGODB_URI='):
                        lines[i] = f'MONGODB_URI={new_uri}'
                        break
                
                with open(env_path, 'w') as f:
                    f.write('\n'.join(lines))
                
                print("✅ Database connection fixed!")
                print("✅ .env file updated!")
                
                return True
            else:
                print("✅ Database URI already includes database name")
                return True
        else:
            print("❌ Missing required environment variables")
            return False
            
    except Exception as e:
        print(f"❌ Error fixing database connection: {e}")
        return False

if __name__ == "__main__":
    success = fix_database_connection()
    
    if success:
        print("\n🎯 NEXT STEPS:")
        print("📌 1. Restart backend server")
        print("📌 2. Test upload -> download flow")
        print("📌 3. Verify both use same database")
        print("\n🚀 Expected result: Download should find files uploaded to Atlas")
    else:
        print("\n❌ Fix failed - manual intervention required")
