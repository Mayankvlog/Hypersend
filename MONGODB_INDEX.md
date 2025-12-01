# MongoDB Setup - Complete Documentation Index

## 📚 Quick Navigation

**For immediate setup (5 minutes):**
→ Start with [`MONGODB_QUICK_START.md`](#quick-start-guide)

**For detailed setup (20 minutes):**
→ Read [`MONGODB_COMPASS_SETUP.md`](#detailed-setup-guide)

**For visual reference:**
→ Check [`MONGODB_SETUP_REFERENCE.md`](#visual-reference)

**For automated setup:**
→ Run [`scripts/seed_mongodb.py`](#automated-seeding-script)

---

## 📖 Documentation Files

### Quick Start Guide
**File:** `MONGODB_QUICK_START.md`
**Length:** ~200 lines
**Best for:** Immediate setup
**Contents:**
- 3 setup options (Automatic, Manual, CLI)
- Quick commands reference
- Troubleshooting basics
- Next steps

### Detailed Setup Guide
**File:** `MONGODB_COMPASS_SETUP.md`
**Length:** ~400 lines
**Best for:** Complete understanding
**Contents:**
- Prerequisites & downloads
- Installation & connection steps
- Database structure overview
- Collection creation (GUI & CLI)
- 3 methods to load data (GUI, Python, JSON)
- Backup & export procedures
- Comprehensive troubleshooting

### Visual Reference
**File:** `MONGODB_SETUP_REFERENCE.md`
**Length:** ~350 lines
**Best for:** Architecture understanding
**Contents:**
- Connection diagrams
- Setup process flows
- File structure
- Data schema reference
- Connection methods comparison
- Performance specs
- Commands quick reference
- Security checklist

### Automated Seeding Script
**File:** `scripts/seed_mongodb.py`
**Type:** Python 3 executable
**Best for:** Production-grade setup
**Contents:**
- Automatic database creation
- Collections setup with indexes
- 6,350+ test documents
- Progress reporting
- Error handling
- Database statistics

---

## 🎯 Choose Your Setup Method

### Method 1: Automatic (⭐ Recommended) - 5 Minutes
```bash
# Start MongoDB
docker-compose up -d mongodb

# Install dependencies
pip install pymongo

# Run seeding script
python scripts/seed_mongodb.py

# Done! Database ready with 6,350 test documents
```
**Best for:** Development, testing, quick setup
**Complexity:** Easy
**Time:** ~5 minutes

### Method 2: MongoDB Compass (GUI) - 15 Minutes
```bash
# Start MongoDB
docker-compose up -d mongodb

# Download MongoDB Compass from mongodb.com
# Launch Compass

# Connect to localhost:27017
# Create collections manually
# Insert test data via GUI
```
**Best for:** Visual learners, understanding structure
**Complexity:** Medium
**Time:** ~15 minutes

### Method 3: Command Line (mongosh) - 20 Minutes
```bash
# Start MongoDB
docker-compose up -d mongodb

# Connect to shell
docker-compose exec mongodb mongosh -u hypersend -p Mayank@#03 --authenticationDatabase admin

# Create collections and insert data manually
```
**Best for:** Advanced users, scripting
**Complexity:** Hard
**Time:** ~20 minutes

---

## 🗂️ What Gets Created

| Component | Quantity | Purpose |
|-----------|----------|---------|
| **Users** | 50 | Test user accounts with email/password |
| **Chats** | 100 | Private and group conversations |
| **Messages** | 5,000 | Chat messages across conversations |
| **Files** | 500 | File metadata and information |
| **Uploads** | 100 | Upload sessions in progress |
| **Refresh Tokens** | 500 | Authentication tokens |
| **Reset Tokens** | 100 | Password reset tokens |
| **TOTAL** | **6,350** | Complete test dataset |

---

## 🔐 Credentials

```
Database Name:     hypersend
Username:          hypersend
Password:          Mayank@#03
Authentication DB: admin
Port:              27017
Replica Set:       rs0
```

**Connection Strings:**
```
Local:  mongodb://hypersend:Mayank@#03@localhost:27017/hypersend?authSource=admin&replicaSet=rs0
VPS:    mongodb://hypersend:Mayank@#03@139.59.82.105:27017/hypersend?authSource=admin&replicaSet=rs0
```

---

## 💻 Quick Commands

### Start/Stop MongoDB
```bash
# Start MongoDB service
docker-compose up -d mongodb

# Check if running
docker-compose ps mongodb

# View logs
docker-compose logs -f mongodb

# Stop MongoDB
docker-compose stop mongodb

# Remove container
docker-compose down mongodb
```

### Seeding Data
```bash
# Automatic seeding (Recommended)
python scripts/seed_mongodb.py

# Check if already done
docker-compose exec mongodb mongosh -u hypersend -p Mayank@#03 --authenticationDatabase admin hypersend
db.users.countDocuments()  # Should show 50
```

### Access Database
```bash
# Connect with MongoDB Compass
→ localhost:27017
→ Username: hypersend
→ Password: Mayank@#03
→ Auth DB: admin

# Connect with shell
docker-compose exec mongodb mongosh -u hypersend -p Mayank@#03 --authenticationDatabase admin hypersend

# View collections
show collections

# Count documents
db.users.countDocuments()
db.chats.countDocuments()
db.messages.countDocuments()

# Find specific document
db.users.findOne({ email: "user1@hypersend.io" })
```

### Backup/Export Data
```bash
# Export collection to JSON
mongoexport --uri "mongodb://hypersend:Mayank@#03@localhost:27017/hypersend?authSource=admin" \
  --collection users \
  --out users.json

# Import collection from JSON
mongoimport --uri "mongodb://hypersend:Mayank@#03@localhost:27017/hypersend?authSource=admin" \
  --collection users \
  --file users.json

# Full database backup
mongodump --uri "mongodb://hypersend:Mayank@#03@localhost:27017/hypersend?authSource=admin" \
  --out ./backup

# Full database restore
mongorestore --uri "mongodb://hypersend:Mayank@#03@localhost:27017/hypersend?authSource=admin" \
  ./backup
```

---

## 🆘 Troubleshooting

### MongoDB Won't Start
```bash
# Check if port 27017 is already in use
netstat -an | findstr 27017

# View error logs
docker-compose logs mongodb

# Restart with clean slate
docker-compose down mongodb
docker-compose up -d mongodb
```

### Connection Refused
```bash
# Verify MongoDB is running
docker-compose ps

# Check firewall (for VPS)
sudo ufw allow 27017

# Verify credentials
docker-compose exec mongodb mongosh -u hypersend -p Mayank@#03 --authenticationDatabase admin
```

### Script Fails to Connect
```bash
# Ensure dependencies installed
pip install pymongo

# Check connection string in script
# Should be: mongodb://hypersend:Mayank@#03@localhost:27017/hypersend?authSource=admin&replicaSet=rs0

# Try connecting directly
python -c "from pymongo import MongoClient; MongoClient('mongodb://hypersend:Mayank@#03@localhost:27017/hypersend?authSource=admin').server_info()"
```

### Data Not Inserting
```bash
# Check if collections exist
docker-compose exec mongodb mongosh -u hypersend -p Mayank@#03 --authenticationDatabase admin hypersend
show collections

# Check collection stats
db.users.stats()

# View any errors
db.messages.find().limit(1)
```

---

## 📊 Database Schema

### Users Collection
```javascript
{
  _id: ObjectId,
  name: "string",
  email: "string" (unique),
  password_hash: "string",
  quota_used: number,
  quota_limit: number,
  created_at: date
}
```

### Chats Collection
```javascript
{
  _id: ObjectId,
  type: "private" or "group",
  name: "string" (optional),
  members: [userId, userId],
  created_at: date
}
```

### Messages Collection
```javascript
{
  _id: ObjectId,
  chat_id: string,
  sender_id: string,
  type: "text" or "file",
  text: "string" (optional),
  file_id: string (optional),
  language: "string",
  created_at: date,
  saved_by: [userId]
}
```

### Files Collection
```javascript
{
  _id: ObjectId,
  upload_id: string,
  file_uuid: string,
  filename: string,
  size: number,
  mime: string,
  owner_id: string,
  chat_id: string,
  storage_path: string,
  checksum: string,
  status: "completed",
  created_at: date
}
```

---

## ✅ Verification Checklist

After setup, verify:

- [ ] MongoDB container is running (`docker-compose ps`)
- [ ] Can connect with credentials (MongoDB Compass or shell)
- [ ] Database `hypersend` exists
- [ ] All 7 collections created
- [ ] Documents inserted (check counts with `countDocuments()`)
- [ ] Indexes created on critical fields
- [ ] No errors in docker logs (`docker-compose logs mongodb`)
- [ ] Application backend can connect to database

---

## 🚀 Next Steps

After MongoDB is set up:

1. **Start Backend:**
   ```bash
   docker-compose up -d backend
   ```

2. **Start Frontend:**
   ```bash
   docker-compose up -d frontend
   ```

3. **Access Application:**
   - Frontend: http://localhost:8550
   - API Docs: http://localhost:8000/docs
   - Health Check: http://localhost:8000/health

4. **Verify Connectivity:**
   ```bash
   # Backend should connect to MongoDB
   docker-compose logs backend | grep -i mongo
   ```

---

## 📞 Support

For issues:

1. **Check logs:**
   ```bash
   docker-compose logs -f mongodb
   ```

2. **Verify credentials:**
   ```bash
   docker-compose exec mongodb mongosh -u hypersend -p Mayank@#03 --authenticationDatabase admin
   ```

3. **Read documentation:**
   - See `MONGODB_COMPASS_SETUP.md` for detailed troubleshooting
   - See `MONGODB_SETUP_REFERENCE.md` for architecture info

4. **Check connection:**
   ```bash
   docker-compose exec backend python -c "
   from backend.database import client
   print('Connected!' if client.server_info() else 'Error')
   "
   ```

---

## 📚 Full Documentation

| File | Purpose | Length |
|------|---------|--------|
| `MONGODB_QUICK_START.md` | Quick reference | 200 lines |
| `MONGODB_COMPASS_SETUP.md` | Detailed guide | 400 lines |
| `MONGODB_SETUP_REFERENCE.md` | Visual reference | 350 lines |
| `scripts/seed_mongodb.py` | Seeding script | 300 lines |
| `MONGODB_INDEX.md` | This file | - |

---

## 🎉 Ready to Go!

Your MongoDB is configured and ready for use. Choose your setup method above and get started!

**Recommended:** Run `python scripts/seed_mongodb.py` for instant setup with 6,350 test documents.

---

**Last Updated:** December 1, 2025  
**Status:** ✅ Complete and Tested  
**Repository:** Mayankvlog/Hypersend  
**Branch:** main
