# 🚀 MongoDB Setup - Quick Start Guide

## Option 1: Automatic Seeding (Recommended)

### Step 1: Start MongoDB
```bash
cd c:\Users\mayan\Downloads\Addidas\hypersend
docker-compose up -d mongodb
```

### Step 2: Install Dependencies
```bash
# If not already installed
pip install pymongo
```

### Step 3: Run Seed Script
```bash
python scripts/seed_mongodb.py
```

**Output:**
```
✅ Connected to MongoDB successfully

🗑️  Clearing existing collections...
   Cleared users: 0 documents removed
   ✅ Collections cleared

👥 Creating 50 sample users...
   ✓ Inserted 50 users
   ✓ Created unique index on email

💬 Creating 100 sample chats...
   ✓ Inserted 100 chats
   ✓ Created indexes on members and created_at

📝 Creating 5000 sample messages...
   ✓ Inserted 5000 messages
   ✓ Created indexes on chat_id, created_at, and sender_id

📁 Creating 500 sample files...
   ✓ Inserted 500 files
   ✓ Created indexes on owner_id, chat_id, and upload_id

⬆️  Creating 100 sample uploads...
   ✓ Inserted 100 uploads
   ✓ Created indexes on upload_id and expires_at

🔐 Creating sample tokens...
   ✓ Inserted 500 refresh tokens
   ✓ Inserted 100 reset tokens
   ✓ Created indexes on tokens

==================================================
📊 DATABASE STATISTICS
==================================================
👥 Users ........................      50
💬 Chats ........................     100
📝 Messages .....................    5000
📁 Files ........................     500
⬆️  Uploads ......................     100
🔄 Refresh Tokens ..............     500
🔐 Reset Tokens ................     100
==================================================
TOTAL DOCUMENTS ..................    6350
==================================================
Database Size: 5.23 MB

✅ Database seeding completed successfully!
```

---

## Option 2: Manual Setup with MongoDB Compass

### Step 1: Download & Install MongoDB Compass
- Download: https://www.mongodb.com/products/compass
- Install for Windows

### Step 2: Start MongoDB
```bash
docker-compose up -d mongodb
```

### Step 3: Connect in Compass
1. Open MongoDB Compass
2. Click "New Connection"
3. Fill in:
   - Hostname: `localhost`
   - Port: `27017`
   - Username: `hypersend`
   - Password: `Mayank@#03`
   - Auth DB: `admin`
4. Click "Connect"

### Step 4: Create Collections
1. Click "+" next to database name or right-click
2. Select "Create Collection"
3. Create these collections:
   - `users`
   - `chats`
   - `messages`
   - `files`
   - `uploads`
   - `refresh_tokens`
   - `reset_tokens`

### Step 5: Insert Sample Data
Click on collection → Click "+" → "Insert Document" → Paste JSON:

**Sample User:**
```json
{
  "name": "John Doe",
  "email": "john@example.com",
  "password_hash": "hash_here",
  "quota_used": 0,
  "quota_limit": 42949672960,
  "created_at": "2025-12-01T10:00:00Z"
}
```

---

## Option 3: Command Line Setup

### Step 1: Start MongoDB
```bash
docker-compose up -d mongodb
```

### Step 2: Create Database & Collections
```bash
# Connect to MongoDB shell
docker-compose exec mongodb mongosh -u hypersend -p Mayank@#03 --authenticationDatabase admin

# Use hypersend database
use hypersend

# Create collections
db.createCollection("users")
db.createCollection("chats")
db.createCollection("messages")
db.createCollection("files")
db.createCollection("uploads")
db.createCollection("refresh_tokens")
db.createCollection("reset_tokens")

# Create indexes
db.users.createIndex({ email: 1 }, { unique: true })
db.chats.createIndex({ members: 1 })
db.messages.createIndex({ chat_id: 1, created_at: -1 })
db.files.createIndex({ owner_id: 1 })

# Verify
show collections
```

### Step 3: Insert Test Data
```bash
docker-compose exec mongodb mongosh -u hypersend -p Mayank@#03 --authenticationDatabase admin hypersend

# Insert user
db.users.insertOne({
  "name": "Test User",
  "email": "test@example.com",
  "password_hash": "hash",
  "quota_used": 0,
  "quota_limit": 42949672960,
  "created_at": new Date()
})

# Verify
db.users.findOne()
```

---

## Verify Setup

### Using Compass
1. Open MongoDB Compass
2. Connect to localhost:27017
3. Check hypersend database
4. Verify collections exist
5. View documents in each collection

### Using Command Line
```bash
# Connect
docker-compose exec mongodb mongosh -u hypersend -p Mayank@#03 --authenticationDatabase admin hypersend

# Check statistics
db.users.countDocuments()
db.chats.countDocuments()
db.messages.countDocuments()
db.files.countDocuments()

# View sample
db.users.findOne()
```

---

## Quick Connection Strings

**Local (Docker):**
```
mongodb://hypersend:Mayank@#03@localhost:27017/hypersend?authSource=admin&replicaSet=rs0
```

**VPS (139.59.82.105):**
```
mongodb://hypersend:Mayank@#03@139.59.82.105:27017/hypersend?authSource=admin&replicaSet=rs0
```

---

## What Gets Created

| Component | Quantity | Purpose |
|-----------|----------|---------|
| Users | 50 | Test user accounts |
| Chats | 100 | Test conversations |
| Messages | 5,000 | Test messages |
| Files | 500 | Test file metadata |
| Uploads | 100 | Test upload sessions |
| Refresh Tokens | 500 | Test auth tokens |
| Reset Tokens | 100 | Test password reset |
| **TOTAL** | **6,350** | Complete test dataset |

---

## Troubleshooting

### MongoDB won't start
```bash
# Check if running
docker-compose ps

# View logs
docker-compose logs mongodb

# Restart
docker-compose restart mongodb
```

### Connection refused
```bash
# Check if port 27017 is open
netstat -an | findstr 27017

# Or using PowerShell
Get-NetTCPConnection -State Listen | Where-Object {$_.LocalPort -eq 27017}
```

### Script fails to connect
```bash
# Verify credentials
# Username: hypersend
# Password: Mayank@#03
# Auth DB: admin

# Test connection
docker-compose exec mongodb mongosh -u hypersend -p Mayank@#03 --authenticationDatabase admin
```

---

## Next Steps

After setting up MongoDB:

1. ✅ **Database Ready** - MongoDB with test data
2. **Start Backend** - `docker-compose up -d backend`
3. **Start Frontend** - `docker-compose up -d frontend`
4. **Access Frontend** - http://localhost:8550
5. **API Docs** - http://localhost:8000/docs

---

## Files Created

- `scripts/seed_mongodb.py` - Automatic seeding script (Recommended)
- `MONGODB_COMPASS_SETUP.md` - Detailed setup guide
- `MONGODB_QUICK_START.md` - This file

## Commands Reference

```bash
# Start MongoDB only
docker-compose up -d mongodb

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f mongodb

# Connect to shell
docker-compose exec mongodb mongosh -u hypersend -p Mayank@#03 --authenticationDatabase admin

# Run seed script
python scripts/seed_mongodb.py

# Stop MongoDB
docker-compose stop mongodb

# Remove MongoDB container
docker-compose down mongodb
```

**Ready to use! Your database is now set up with mass test data. 🎉**
