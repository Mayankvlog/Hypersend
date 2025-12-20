#!/usr/bin/env python3
"""
MongoDB Seed Script - Zaply Database
Populates MongoDB with realistic sample data for testing
"""

from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from datetime import datetime, timedelta
import hashlib
import secrets
import sys

# Configuration (points directly to your DigitalOcean VPS MongoDB)
MONGO_URI = "mongodb://hypersend:Mayank@#03@139.59.82.105:27017/hypersend?authSource=admin&replicaSet=admin"
DB_NAME = "hypersend"

# Sample data
SAMPLE_MESSAGES = [
    "Hey, how are you?",
    "Let me send you this file",
    "Thanks for sharing!",
    "See you later",
    "Great work!",
    "Can you help me?",
    "Sure, no problem",
    "Perfect!",
    "Take care",
    "See you soon",
    "What's up?",
    "Talk to you later",
    "Sounds good",
    "I'll check it out",
    "Thanks for the update"
]

SAMPLE_NAMES = [
    "Alice Johnson", "Bob Smith", "Charlie Brown", "Diana Prince", "Evan Turner",
    "Fiona Green", "George Wilson", "Hannah Martinez", "Isaac Newton", "Julia Roberts",
    "Kevin Hart", "Laura Palmer", "Michael Scott", "Nancy Drew", "Oscar Wilde",
    "Patricia Davis", "Quincy Adams", "Rachel Green", "Samuel Johnson", "Tina Turner"
]

FILE_TYPES = {
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "txt": "text/plain",
    "jpg": "image/jpeg",
    "png": "image/png",
    "zip": "application/zip"
}

class ZaplySeeder:
    def __init__(self, mongo_uri):
        self.client = None
        self.db = None
        self.mongo_uri = mongo_uri
        
    def connect(self):
        """Connect to MongoDB"""
        try:
            self.client = MongoClient(self.mongo_uri, serverSelectionTimeoutMS=5000)
            self.client.admin.command('ping')
            self.db = self.client[DB_NAME]
            print("✅ Connected to MongoDB successfully")
            return True
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            print(f"❌ Failed to connect to MongoDB: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from MongoDB"""
        if self.client:
            self.client.close()
            print("✅ Disconnected from MongoDB")
    
    def hash_password(self, password):
        """Hash password using SHA256 (use bcrypt in production)"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def clear_database(self):
        """Clear all collections"""
        print("\n🗑️  Clearing existing collections...")
        collections = ["users", "chats", "messages", "files", "uploads", "refresh_tokens", "reset_tokens"]
        
        for collection_name in collections:
            count = self.db[collection_name].delete_many({}).deleted_count
            if count > 0:
                print(f"   Cleared {collection_name}: {count} documents removed")
        
        print("✅ Collections cleared")
    
    def create_users(self, count=50):
        """Create sample users"""
        print(f"\n👥 Creating {count} sample users...")
        
        users = []
        for i in range(1, count + 1):
            users.append({
                "name": SAMPLE_NAMES[i % len(SAMPLE_NAMES)],
                "email": f"user{i}@zaply.io",
                "password_hash": self.hash_password(f"Password{i}@123"),
                "quota_used": 0,
                "quota_limit": 42949672960,  # 40GB
                "created_at": datetime.utcnow() - timedelta(days=count - i)
            })
        
        result = self.db.users.insert_many(users)
        print(f"   ✓ Inserted {len(result.inserted_ids)} users")
        
        # Create index for email
        self.db.users.create_index("email", unique=True)
        print("   ✓ Created unique index on email")
        
        return [str(uid) for uid in result.inserted_ids]
    
    def create_chats(self, user_ids, count=100):
        """Create sample chats"""
        print(f"\n💬 Creating {count} sample chats...")
        
        chats = []
        for i in range(1, count + 1):
            # Create private or group chats
            is_group = i % 3 == 0
            num_members = (i % 3) + 2 if is_group else 2  # 2-4 members for groups
            
            members = []
            for j in range(num_members):
                members.append(user_ids[(i + j) % len(user_ids)])
            
            chats.append({
                "type": "group" if is_group else "private",
                "name": f"Group {i}" if is_group else None,
                "members": list(set(members)),  # Remove duplicates
                "created_at": datetime.utcnow() - timedelta(hours=i)
            })
        
        result = self.db.chats.insert_many(chats)
        print(f"   ✓ Inserted {len(result.inserted_ids)} chats")
        
        # Create indexes
        self.db.chats.create_index("members")
        self.db.chats.create_index("created_at")
        print("   ✓ Created indexes on members and created_at")
        
        return [str(cid) for cid in result.inserted_ids]
    
    def create_messages(self, chat_ids, user_ids, count=5000):
        """Create sample messages"""
        print(f"\n📝 Creating {count} sample messages...")
        
        messages = []
        for i in range(1, count + 1):
            chat_idx = i % len(chat_ids)
            sender_idx = i % len(user_ids)
            is_file = i % 15 == 0  # 1 in 15 messages is a file
            
            messages.append({
                "chat_id": chat_ids[chat_idx],
                "sender_id": user_ids[sender_idx],
                "type": "file" if is_file else "text",
                "text": SAMPLE_MESSAGES[(i + sender_idx) % len(SAMPLE_MESSAGES)] if not is_file else None,
                "file_id": f"file_{i}" if is_file else None,
                "language": "en",
                "created_at": datetime.utcnow() - timedelta(minutes=count - i),
                "saved_by": []
            })
        
        result = self.db.messages.insert_many(messages)
        print(f"   ✓ Inserted {len(result.inserted_ids)} messages")
        
        # Create indexes
        self.db.messages.create_index([("chat_id", 1), ("created_at", -1)])
        self.db.messages.create_index("sender_id")
        print("   ✓ Created indexes on chat_id, created_at, and sender_id")
        
        return [str(mid) for mid in result.inserted_ids]
    
    def create_files(self, user_ids, chat_ids, count=500):
        """Create sample files"""
        print(f"\n📁 Creating {count} sample files...")
        
        files = []
        file_type_keys = list(FILE_TYPES.keys())
        
        for i in range(1, count + 1):
            file_type = file_type_keys[i % len(file_type_keys)]
            mime_type = FILE_TYPES[file_type]
            owner_idx = i % len(user_ids)
            chat_idx = i % len(chat_ids)
            
            # Size: 1MB to 1GB
            size = ((i * 50) % 1024) + 1
            size_bytes = size * 1024 * 1024
            
            files.append({
                "upload_id": f"upload_{i}",
                "file_uuid": f"uuid_{secrets.token_hex(8)}",
                "filename": f"document_{i}.{file_type}",
                "size": size_bytes,
                "mime": mime_type,
                "owner_id": user_ids[owner_idx],
                "chat_id": chat_ids[chat_idx],
                "storage_path": f"/data/uploads/{i}/{file_type}",
                "checksum": f"sha256_{secrets.token_hex(16)}",
                "status": "completed",
                "created_at": datetime.utcnow() - timedelta(days=i % 30)
            })
        
        result = self.db.files.insert_many(files)
        print(f"   ✓ Inserted {len(result.inserted_ids)} files")
        
        # Create indexes
        self.db.files.create_index([("owner_id", 1), ("chat_id", 1)])
        self.db.files.create_index("upload_id")
        print("   ✓ Created indexes on owner_id, chat_id, and upload_id")
        
        return [str(fid) for fid in result.inserted_ids]
    
    def create_uploads(self, user_ids, count=100):
        """Create sample uploads in progress"""
        print(f"\n⬆️  Creating {count} sample uploads...")
        
        uploads = []
        for i in range(1, count + 1):
            total_chunks = (i % 100) + 1
            chunk_size = 4194304  # 4MB
            received_chunks = list(range(0, min(total_chunks // 2, total_chunks)))
            
            uploads.append({
                "upload_id": f"upload_session_{i}",
                "owner_id": user_ids[i % len(user_ids)],
                "filename": f"upload_{i}.bin",
                "size": total_chunks * chunk_size,
                "mime": "application/octet-stream",
                "chat_id": f"chat_{i % 100}",
                "total_chunks": total_chunks,
                "chunk_size": chunk_size,
                "received_chunks": received_chunks,
                "checksum": f"sha256_{secrets.token_hex(16)}",
                "expires_at": datetime.utcnow() + timedelta(hours=24),
                "created_at": datetime.utcnow() - timedelta(hours=i)
            })
        
        result = self.db.uploads.insert_many(uploads)
        print(f"   ✓ Inserted {len(result.inserted_ids)} uploads")
        
        # Create indexes
        self.db.uploads.create_index("upload_id")
        self.db.uploads.create_index("expires_at")
        print("   ✓ Created indexes on upload_id and expires_at")
    
    def create_tokens(self, user_ids, refresh_count=500, reset_count=100):
        """Create sample refresh and reset tokens"""
        print("\n🔐 Creating sample tokens...")
        
        # Refresh tokens
        refresh_tokens = []
        for i in range(1, refresh_count + 1):
            refresh_tokens.append({
                "user_id": user_ids[i % len(user_ids)],
                "token": secrets.token_urlsafe(32),
                "expires_at": datetime.utcnow() + timedelta(days=30),
                "created_at": datetime.utcnow() - timedelta(hours=i)
            })
        
        result = self.db.refresh_tokens.insert_many(refresh_tokens)
        print(f"   ✓ Inserted {len(result.inserted_ids)} refresh tokens")
        
        # Reset tokens
        reset_tokens = []
        for i in range(1, reset_count + 1):
            reset_tokens.append({
                "user_id": user_ids[i % len(user_ids)],
                "token": secrets.token_urlsafe(32),
                "email": f"user{i % len(user_ids)}@zaply.io",
                "expires_at": datetime.utcnow() + timedelta(hours=2),
                "created_at": datetime.utcnow() - timedelta(minutes=i)
            })
        
        result = self.db.reset_tokens.insert_many(reset_tokens)
        print(f"   ✓ Inserted {len(result.inserted_ids)} reset tokens")
        
        # Create indexes
        self.db.refresh_tokens.create_index("user_id")
        self.db.refresh_tokens.create_index("expires_at")
        self.db.reset_tokens.create_index("user_id")
        self.db.reset_tokens.create_index("expires_at")
        print("   ✓ Created indexes on tokens")
    
    def print_statistics(self):
        """Print database statistics"""
        print("\n" + "="*50)
        print("📊 DATABASE STATISTICS")
        print("="*50)
        
        collections = {
            "users": "👥 Users",
            "chats": "💬 Chats",
            "messages": "📝 Messages",
            "files": "📁 Files",
            "uploads": "⬆️  Uploads",
            "refresh_tokens": "🔄 Refresh Tokens",
            "reset_tokens": "🔐 Reset Tokens"
        }
        
        total_docs = 0
        for collection_name, label in collections.items():
            count = self.db[collection_name].count_documents({})
            total_docs += count
            print(f"{label:.<30} {count:>6}")
        
        print("="*50)
        print(f"{'TOTAL DOCUMENTS':.<30} {total_docs:>6}")
        print("="*50)
        
        # Database size
        try:
            stats = self.db.command("dbstats")
            size_mb = stats.get("dataSize", 0) / (1024 * 1024)
            print(f"Database Size: {size_mb:.2f} MB")
        except Exception:
            pass
    
    def seed(self):
        """Execute complete seeding process"""
        print("\n" + "="*50)
        print("🌱 ZAPLY DATABASE SEEDING")
        print("="*50)
        
        if not self.connect():
            return False
        
        try:
            self.clear_database()
            
            # Create data
            user_ids = self.create_users(50)
            chat_ids = self.create_chats(user_ids, 100)
            self.create_messages(chat_ids, user_ids, 5000)
            self.create_files(user_ids, chat_ids, 500)
            self.create_uploads(user_ids, 100)
            self.create_tokens(user_ids, 500, 100)
            
            self.print_statistics()
            
            print("\n✅ Database seeding completed successfully!")
            print("\n💡 Next Steps:")
            print("   1. Open MongoDB Compass")
            print("   2. Connect to: 139.59.82.105:27017")
            print("   3. Username: hypersend")
            print("   4. Password: Mayank@#03")
            print("   5. Browse hypersend database")
            print("   6. Start your Zaply application")
            
            return True
            
        except Exception as e:
            print(f"\n❌ Error during seeding: {e}")
            import traceback
            traceback.print_exc()
            return False
        
        finally:
            self.disconnect()

def main():
    """Main entry point"""
    seeder = ZaplySeeder(MONGO_URI)
    success = seeder.seed()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
