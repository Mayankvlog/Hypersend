# MongoDB Compass Setup Guide - Hypersend Database

**Complete guide for setting up MongoDB with mass test data using MongoDB Compass**

---

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation & Connection](#installation--connection)
3. [Database Structure](#database-structure)
4. [Setting Up Collections](#setting-up-collections)
5. [Loading Mass Data](#loading-mass-data)
6. [Verification & Testing](#verification--testing)
7. [Backup & Export](#backup--export)

---

## Prerequisites

### Software Required
- **MongoDB 7.0** (Running locally or on VPS 139.59.82.105)
- **MongoDB Compass** (GUI tool for MongoDB)
- **Docker & Docker Compose** (for running MongoDB)

### Download Links
- **MongoDB Compass**: https://www.mongodb.com/products/compass
- **Docker Desktop**: https://www.docker.com/products/docker-desktop

---

## Installation & Connection

### Step 1: Start MongoDB with Docker Compose

```bash
# Navigate to your Hypersend project
cd c:\Users\mayan\Downloads\Addidas\hypersend

# Start MongoDB service
docker-compose up -d mongodb

# Verify MongoDB is running
docker-compose ps
```

**Expected Output:**
```
NAME                  STATUS
hypersend_mongodb     Up (healthy)
```

### Step 2: Install MongoDB Compass

1. Download from: https://www.mongodb.com/products/compass
2. Run installer for Windows
3. Launch MongoDB Compass

### Step 3: Connect to MongoDB

**Connection Method 1: Local Docker (Recommended for Development)**

1. Open MongoDB Compass
2. Click "New Connection"
3. Fill in connection details:
   ```
   Hostname:  localhost
   Port:      27017
   Username:  hypersend
   Password:  Mayank@#03
   Auth DB:   admin
   ```
4. Click "Connect"

**Connection Method 2: VPS Connection (For Production)**

1. Open MongoDB Compass
2. Click "New Connection"
3. Fill in connection details:
   ```
   Hostname:  139.59.82.105
   Port:      27017
   Username:  hypersend
   Password:  Mayank@#03
   Auth DB:   admin
   ```
4. **Note:** This only works if port 27017 is open on your VPS firewall
5. Click "Connect"

**Connection String Format:**
```
mongodb://hypersend:Mayank@#03@localhost:27017/?authSource=admin&replicaSet=rs0
```

---

## Database Structure

### Collections in Hypersend Database

Your `hypersend` database will contain these collections:

| Collection | Purpose | Documents |
|-----------|---------|-----------|
| `users` | User accounts | ~50-100 users |
| `chats` | Chat rooms/conversations | ~100-500 chats |
| `messages` | Chat messages | ~10,000-50,000 messages |
| `files` | File metadata | ~500-2,000 files |
| `uploads` | Upload sessions | ~100-500 uploads |
| `refresh_tokens` | Auth tokens | ~500-2,000 tokens |
| `reset_tokens` | Password reset tokens | ~50-200 tokens |

---

## Setting Up Collections

### Using MongoDB Compass GUI

#### Step 1: Create Database

1. In Compass, right-click in left panel or click "+" next to databases
2. Enter database name: `hypersend`
3. Enter collection name: `users`
4. Click "Create Database"

#### Step 2: Create Collections

Repeat for each collection:

1. Right-click on `hypersend` database
2. Select "Create Collection"
3. Enter collection name
4. Click "Create"

**Collections to Create:**
- `users`
- `chats`
- `messages`
- `files`
- `uploads`
- `refresh_tokens`
- `reset_tokens`

#### Step 3: Create Indexes (Important!)

For each collection, create indexes in Compass:

**For `users` collection:**
```
Field: email
Options: Unique ✓
```

**For `files` collection:**
```
Field: upload_id
Field: owner_id
Field: chat_id
```

**For `messages` collection:**
```
Field: chat_id
Field: sender_id
Field: created_at
```

### Using MongoDB Shell (Alternative)

If you prefer command line:

```bash
# Connect to MongoDB
docker-compose exec mongodb mongosh -u hypersend -p Mayank@#03 --authenticationDatabase admin

# Create database and collections
use hypersend

db.createCollection("users", {
  validator: {
    $jsonSchema: {
      bsonType: "object",
      required: ["name", "email", "password_hash"],
      properties: {
        _id: { bsonType: "objectId" },
        name: { bsonType: "string" },
        email: { bsonType: "string" },
        password_hash: { bsonType: "string" },
        quota_used: { bsonType: "int" },
        quota_limit: { bsonType: "long" },
        created_at: { bsonType: "date" }
      }
    }
  }
})

# Create indexes
db.users.createIndex({ email: 1 }, { unique: true })
db.chats.createIndex({ members: 1 })
db.messages.createIndex({ chat_id: 1, created_at: -1 })
db.files.createIndex({ owner_id: 1, chat_id: 1 })

# Verify collections
show collections
```

---

## Loading Mass Data

### Method 1: Using Compass GUI (For Small Datasets)

#### Single Document Insert

1. Open `hypersend` database in Compass
2. Select `users` collection
3. Click "Insert Document"
4. Paste JSON document:

```json
{
  "name": "John Doe",
  "email": "john@example.com",
  "password_hash": "$2b$12$...",
  "quota_used": 0,
  "quota_limit": 42949672960,
  "created_at": "2025-12-01T10:00:00.000Z"
}
```

5. Click "Insert"

#### Bulk Insert

1. Click "Insert Document"
2. Click "Insert from text" (curly braces icon)
3. Paste multiple JSON documents (one per line):

```json
{ "name": "User 1", "email": "user1@example.com", "password_hash": "hash1", "quota_used": 0, "quota_limit": 42949672960, "created_at": "2025-12-01T10:00:00.000Z" }
{ "name": "User 2", "email": "user2@example.com", "password_hash": "hash2", "quota_used": 0, "quota_limit": 42949672960, "created_at": "2025-12-01T10:01:00.000Z" }
{ "name": "User 3", "email": "user3@example.com", "password_hash": "hash3", "quota_used": 0, "quota_limit": 42949672960, "created_at": "2025-12-01T10:02:00.000Z" }
```

4. Click "Insert"

### Method 2: Using Python Script (For Large Datasets - Recommended)

Create file: `scripts/seed_mongodb.py`

```python
from pymongo import MongoClient
from datetime import datetime, timedelta
import hashlib
import json

# MongoDB Connection
MONGO_URI = "mongodb://hypersend:Mayank@#03@localhost:27017/hypersend?authSource=admin&replicaSet=rs0"
client = MongoClient(MONGO_URI)
db = client.hypersend

def hash_password(password):
    """Simple password hash (use bcrypt in production)"""
    return hashlib.sha256(password.encode()).hexdigest()

def create_sample_users(count=50):
    """Create sample users"""
    users = []
    for i in range(1, count + 1):
        users.append({
            "name": f"User {i}",
            "email": f"user{i}@example.com",
            "password_hash": hash_password(f"password{i}"),
            "quota_used": 0,
            "quota_limit": 42949672960,
            "created_at": datetime.utcnow() - timedelta(days=i)
        })
    return users

def create_sample_chats(user_ids, count=100):
    """Create sample chats"""
    chats = []
    for i in range(1, count + 1):
        # Random members from users
        members = [user_ids[i % len(user_ids)], user_ids[(i + 1) % len(user_ids)]]
        chats.append({
            "type": "private" if i % 2 == 0 else "group",
            "name": f"Chat {i}" if i % 2 != 0 else None,
            "members": members,
            "created_at": datetime.utcnow() - timedelta(hours=i)
        })
    return chats

def create_sample_messages(chat_ids, user_ids, count=1000):
    """Create sample messages"""
    messages = []
    texts = [
        "Hey, how are you?",
        "Let me send you this file",
        "Thanks for sharing!",
        "See you later",
        "Great work!",
        "Can you help me?",
        "Sure, no problem",
        "Perfect!",
        "Take care",
        "See you soon"
    ]
    
    for i in range(1, count + 1):
        messages.append({
            "chat_id": chat_ids[i % len(chat_ids)],
            "sender_id": user_ids[i % len(user_ids)],
            "type": "text" if i % 10 != 0 else "file",
            "text": texts[i % len(texts)] if i % 10 != 0 else None,
            "file_id": f"file_{i}" if i % 10 == 0 else None,
            "language": "en",
            "created_at": datetime.utcnow() - timedelta(minutes=i),
            "saved_by": []
        })
    return messages

def create_sample_files(user_ids, chat_ids, count=500):
    """Create sample files"""
    files = []
    file_types = ["pdf", "docx", "xlsx", "pptx", "txt", "jpg", "png", "zip"]
    
    for i in range(1, count + 1):
        file_type = file_types[i % len(file_types)]
        files.append({
            "upload_id": f"upload_{i}",
            "file_uuid": f"uuid_{i}",
            "filename": f"document_{i}.{file_type}",
            "size": (i * 1024 * 1024) % 1073741824,  # 0-1GB random
            "mime": f"application/{file_type}",
            "owner_id": user_ids[i % len(user_ids)],
            "chat_id": chat_ids[i % len(chat_ids)],
            "storage_path": f"/data/uploads/{i}/{file_type}",
            "checksum": f"checksum_{i}",
            "status": "completed",
            "created_at": datetime.utcnow() - timedelta(days=i % 30)
        })
    return files

def seed_database():
    """Seed all collections with sample data"""
    
    print("🔄 Starting database seeding...")
    
    # Clear existing data
    print("🗑️  Clearing existing collections...")
    collections = ["users", "chats", "messages", "files", "uploads", "refresh_tokens", "reset_tokens"]
    for collection in collections:
        db[collection].delete_many({})
    
    # Create Users
    print("👥 Creating 50 sample users...")
    users = create_sample_users(50)
    result = db.users.insert_many(users)
    user_ids = [str(uid) for uid in result.inserted_ids]
    print(f"✓ Inserted {len(user_ids)} users")
    
    # Create Chats
    print("💬 Creating 100 sample chats...")
    chats = create_sample_chats(user_ids, 100)
    result = db.chats.insert_many(chats)
    chat_ids = [str(cid) for cid in result.inserted_ids]
    print(f"✓ Inserted {len(chat_ids)} chats")
    
    # Create Messages
    print("📝 Creating 5000 sample messages...")
    messages = create_sample_messages(chat_ids, user_ids, 5000)
    result = db.messages.insert_many(messages)
    print(f"✓ Inserted {len(result.inserted_ids)} messages")
    
    # Create Files
    print("📁 Creating 500 sample files...")
    files = create_sample_files(user_ids, chat_ids, 500)
    result = db.files.insert_many(files)
    print(f"✓ Inserted {len(result.inserted_ids)} files")
    
    # Summary Statistics
    print("\n✅ Database seeding complete!")
    print("\n📊 Summary Statistics:")
    print(f"  Users:     {db.users.count_documents({})}")
    print(f"  Chats:     {db.chats.count_documents({})}")
    print(f"  Messages:  {db.messages.count_documents({})}")
    print(f"  Files:     {db.files.count_documents({})}")
    print(f"  Uploads:   {db.uploads.count_documents({})}")
    print(f"  Refresh Tokens: {db.refresh_tokens.count_documents({})}")
    print(f"  Reset Tokens:   {db.reset_tokens.count_documents({})}")

if __name__ == "__main__":
    try:
        seed_database()
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        client.close()
```

**Run the Script:**

```bash
# Install MongoDB driver
pip install pymongo

# Run seeding script
python scripts/seed_mongodb.py
```

### Method 3: Import from JSON File

#### Create JSON Export File

Save as `data/sample_data.json`:

```json
{
  "users": [
    { "name": "User 1", "email": "user1@example.com", "password_hash": "hash1", "quota_used": 0, "quota_limit": 42949672960, "created_at": "2025-12-01T10:00:00Z" },
    { "name": "User 2", "email": "user2@example.com", "password_hash": "hash2", "quota_used": 0, "quota_limit": 42949672960, "created_at": "2025-12-01T10:01:00Z" }
  ],
  "chats": [
    { "type": "private", "name": null, "members": ["user1", "user2"], "created_at": "2025-12-01T10:00:00Z" }
  ],
  "messages": [
    { "chat_id": "chat1", "sender_id": "user1", "type": "text", "text": "Hello!", "language": "en", "created_at": "2025-12-01T10:00:00Z", "saved_by": [] }
  ]
}
```

#### Import Using Compass

1. Open Collection
2. Click "+" button next to documents
3. Select "Import" → "Import JSON"
4. Select your JSON file
5. Click "Import"

---

## Verification & Testing

### Using MongoDB Compass

#### View Statistics

1. Open database in Compass
2. Click on collection name
3. Check document count at top
4. Click "Statistics" tab for storage info

#### Query Examples

**Find all users:**
```json
{}
```

**Find user by email:**
```json
{ "email": "user1@example.com" }
```

**Find messages in specific chat:**
```json
{ "chat_id": "ObjectId(...)" }
```

**Count documents:**
```json
// In Compass Aggregation Pipeline:
[
  { "$count": "total" }
]
```

### Using MongoDB Shell

```bash
# Connect to MongoDB
docker-compose exec mongodb mongosh -u hypersend -p Mayank@#03 --authenticationDatabase admin hypersend

# Check counts
db.users.countDocuments()
db.chats.countDocuments()
db.messages.countDocuments()
db.files.countDocuments()

# View sample document
db.users.findOne()

# Find by email
db.users.findOne({ email: "user1@example.com" })

# Get collection stats
db.users.stats()
```

---

## Backup & Export

### Export Data from Compass

#### Export Entire Collection

1. Open collection in Compass
2. Click "Export" button
3. Choose format: JSON or CSV
4. Select all documents
5. Click "Export"

#### Export with Query

1. Open collection in Compass
2. Add filter (e.g., `{ "created_at": { "$gte": ISODate("2025-11-01") } }`)
3. Click "Export"
4. Select documents to export
5. Click "Export"

### Export Using MongoDB Tools

```bash
# Export collection to JSON
mongoexport --uri "mongodb://hypersend:Mayank@#03@localhost:27017/hypersend?authSource=admin" \
  --collection users \
  --out users.json

# Export with query
mongoexport --uri "mongodb://hypersend:Mayank@#03@localhost:27017/hypersend?authSource=admin" \
  --collection messages \
  --query '{ "created_at": { "$gte": ISODate("2025-11-01") } }' \
  --out recent_messages.json

# Import collection from JSON
mongoimport --uri "mongodb://hypersend:Mayank@#03@localhost:27017/hypersend?authSource=admin" \
  --collection users \
  --file users.json
```

### Backup Entire Database

```bash
# Backup database
mongodump --uri "mongodb://hypersend:Mayank@#03@localhost:27017/hypersend?authSource=admin" \
  --out ./backup/hypersend_backup_$(date +%Y%m%d_%H%M%S)

# Restore database
mongorestore --uri "mongodb://hypersend:Mayank@#03@localhost:27017/hypersend?authSource=admin" \
  ./backup/hypersend_backup_20251201_100000
```

---

## Troubleshooting

### Connection Issues

**"Connection refused"**
```bash
# Check if MongoDB is running
docker-compose ps

# View MongoDB logs
docker-compose logs mongodb

# Restart MongoDB
docker-compose restart mongodb
```

**"Authentication failed"**
- Verify credentials in Compass: `hypersend` / `Mayank@#03`
- Verify auth database is set to: `admin`
- Check .env file has correct MONGO_PASSWORD

**"Cannot connect to 139.59.82.105"**
- Verify port 27017 is open on VPS firewall
- Check VPS IP is correct
- Try connecting locally first

### Data Issues

**"Duplicate key error"**
- Email must be unique in users collection
- Remove duplicate email before inserting
- Update index: `db.users.createIndex({ email: 1 }, { unique: true })`

**"Large dataset import timeout"**
- Increase import timeout in Compass settings
- Import in batches
- Use command line mongoimport instead

**"Storage path issues"**
- Verify `/data` directory exists and has write permissions
- Check Docker volume mounts in docker-compose.yml
- Run: `docker-compose exec backend ls -la /data`

---

## Performance Tips

1. **Create Indexes**: Improves query speed
   - Index frequently queried fields
   - Use compound indexes for multi-field queries

2. **Batch Operations**: Insert/update many at once
   - Use `insertMany()` instead of individual inserts
   - Use bulk operations for updates

3. **Monitor Database Size**
   ```bash
   docker-compose exec mongodb mongosh -u hypersend -p Mayank@#03 --authenticationDatabase admin
   use hypersend
   db.stats()
   ```

4. **Clean Old Data**
   ```javascript
   // Remove messages older than 30 days
   db.messages.deleteMany({ 
     "created_at": { 
       "$lt": new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) 
     } 
   })
   ```

---

## Summary

✅ **You now have:**
- MongoDB running with authentication
- MongoDB Compass connected
- Collections created with proper indexes
- Sample data seeding options
- Backup/export procedures
- Query examples
- Troubleshooting guide

**Next Steps:**
1. Install MongoDB Compass
2. Connect to your local/VPS MongoDB
3. Create collections
4. Load sample data using Python script (Method 2)
5. Verify data in Compass
6. Start using with your Hypersend application

---

**Questions?** Check docker-compose logs or MongoDB Compass documentation.
