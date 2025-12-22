# MongoDB Authentication Fix

## Problem
The backend is failing with: `Authentication failed` because the MongoDB user `hypersend` doesn't exist or has the wrong password.

## Solution

You have **two options** to fix this:

### Option 1: Recreate MongoDB (RECOMMENDED - Fresh Start)

This will delete all existing data and create a fresh MongoDB with the correct user:

```bash
# Stop all containers
docker compose down

# Delete the MongoDB volume (THIS WILL DELETE ALL DATA!)
docker volume rm hypersend_mongodb_data hypersend_mongodb_config

# Start fresh (mongo-init.js will create the user automatically)
docker compose up -d --build

# Check status
docker compose ps
docker logs hypersend_backend
```

### Option 2: Manually Create User (Keep Existing Data)

If you want to keep existing MongoDB data, create the user manually:

```bash
# Connect to MongoDB container
docker exec -it hypersend_mongodb mongosh -u ${MONGO_USER:-hypersend} -p ${MONGO_PASSWORD} --authenticationDatabase admin

# In the MongoDB shell, run:
use admin
db.createUser({
  user: "hypersend",
  pwd: process.env.MONGO_PASSWORD || "YOUR_PASSWORD_HERE",
  roles: [
    { role: "readWrite", db: "hypersend" },
    { role: "dbAdmin", db: "hypersend" }
  ]
})
exit

# Restart backend
docker compose restart backend
```

### Option 3: Update .env File

Make sure your `.env` file has the correct password:

```bash
# Edit .env file
nano .env

# Make sure these lines exist:
MONGO_USER=hypersend
MONGO_PASSWORD=Mayank@#03  # Or whatever password you want
SECRET_KEY=<generate-a-long-random-string>

# Save and restart
docker compose down
docker compose up -d --build
```

## Verification

After applying the fix, verify it worked:

```bash
# Check all containers are healthy
docker compose ps

# Check backend logs (should show successful startup)
docker logs hypersend_backend | tail -20

# Test the API
curl http://localhost:8000/health
```

You should see:
```json
{"status": "healthy"}
```

## What Changed

1. Added `mongo-init.js` - Automatically creates the hypersend user on first MongoDB startup
2. Updated `docker-compose.yml` - Mounts the init script into MongoDB container
3. The init script only runs on FIRST startup, so you need to delete the volume or create the user manually

## Next Steps

Choose one of the options above and run the commands on your server.
