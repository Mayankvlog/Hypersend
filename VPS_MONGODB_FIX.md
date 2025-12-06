# 🔧 VPS MongoDB Connection FIX - COMPLETE SOLUTION

## Problem Summary
- ❌ Backend showing "Unable to connect" error at http://139.59.82.105:8000
- ❌ Local mongod service failing (exit-code 14)
- ❌ Docker MongoDB can't connect from backend container
- ❌ Port 27017 conflicts between local service and Docker

## Root Cause
The docker-compose.yml was configured with **hardcoded external VPS IP** (139.59.82.105:27017) for MongoDB connection, but Docker containers communicate via **internal service names** (mongodb:27017) on the private Docker network.

## ✅ SOLUTIONS COMMITTED TO GITHUB

### Commit eb7acf2 - MongoDB URI Fix
```
- docker-compose.yml: MONGODB_URI now uses 'mongodb:27017' (Docker service name)
- backend/config.py: Default updated to use Docker service name
- Purpose: Enable container-to-container communication on internal network
```

### Commit 79c6429 - Diagnostic & Fix Scripts
```
+ FIX_VPS.sh - Automated one-command fix for all MongoDB issues
+ DIAGNOSE_VPS.sh - Diagnostic script to check current status
+ Updated README.md with comprehensive MongoDB troubleshooting
```

---

## 🚀 HOW TO FIX ON YOUR VPS (OPTION 1 - AUTOMATIC)

### Fastest Method: Run the automated fix script
```bash
# SSH to your VPS
ssh root@139.59.82.105

# Navigate to project
cd /hypersend/Hypersend

# Pull latest changes
git pull origin main

# Run the fix script
bash FIX_VPS.sh
```

This will:
1. ✅ Pull latest code from GitHub (includes MongoDB URI fix)
2. ✅ Stop and disable local mongod service
3. ✅ Kill any process using port 27017
4. ✅ Clean up Docker volumes
5. ✅ Build and start all services
6. ✅ Wait 60 seconds for services to initialize
7. ✅ Show status and test connectivity

---

## 🔍 HOW TO FIX ON YOUR VPS (OPTION 2 - MANUAL)

If you prefer manual steps:

```bash
# SSH to VPS
ssh root@139.59.82.105
cd /hypersend/Hypersend

# Step 1: Update code
git pull origin main

# Step 2: Stop local MongoDB service (causes port conflicts)
sudo systemctl stop mongod
sudo systemctl disable mongod

# Step 3: Free port 27017
sudo lsof -ti :27017 | xargs -r sudo kill -9

# Step 4: Clean Docker resources
docker compose down -v
docker volume rm hypersend_mongodb_data hypersend_mongodb_config 2>/dev/null || true

# Step 5: Rebuild and start all services
docker compose up -d --build

# Step 6: Wait for services to initialize
sleep 60

# Step 7: Check status
docker compose ps
```

---

## ✅ VERIFICATION STEPS

### After running fix, verify everything works:

```bash
# 1. Check all services are running and HEALTHY
docker compose ps
# Expected: All 4 services (nginx, backend, frontend, mongodb) should show Status: Up

# 2. Test backend health check locally
curl http://localhost:8000/health
# Expected: Returns JSON with status

# 3. Check MongoDB logs
docker compose logs mongodb --tail=5

# 4. Check backend logs for MongoDB connection
docker compose logs backend --tail=20
# Should show: Connected to MongoDB, or similar success message

# 5. Test external access (from your local machine)
curl http://139.59.82.105:8000/health
# Expected: Returns JSON with status (no "Unable to connect")
```

---

## 📊 What Changed in the Code

### docker-compose.yml (Line 73)
**BEFORE:**
```yaml
MONGODB_URI: mongodb://hypersend:Mayank%40%2303@139.59.82.105:27017/hypersend?authSource=admin
```

**AFTER:**
```yaml
MONGODB_URI: mongodb://hypersend:Mayank%40%2303@mongodb:27017/hypersend?authSource=admin
```

### backend/config.py (Line 17)
**BEFORE:**
```python
MONGODB_URI: str = os.getenv("MONGODB_URI", "mongodb://hypersend:Mayank%40%2303@139.59.82.105:27017/hypersend?authSource=admin")
```

**AFTER:**
```python
MONGODB_URI: str = os.getenv("MONGODB_URI", "mongodb://hypersend:Mayank%40%2303@mongodb:27017/hypersend?authSource=admin")
```

### Why This Matters
- **Docker Network**: Services communicate via private network 172.20.0.0/16
- **Service Discovery**: Docker DNS resolves `mongodb` to the MongoDB container's internal IP
- **External Access**: Still accessible on port 27017 from outside Docker for remote connections
- **Priority**: Environment variable > docker-compose.yml > config.py default

---

## 🐛 WHAT WAS CAUSING THE ERROR

Your Firefox error **"Unable to connect to 139.59.82.105:8000"** happened because:

1. ❌ Backend started but couldn't connect to MongoDB on `139.59.82.105:27017`
2. ❌ Backend health check failed after 60 seconds
3. ❌ Backend restarted (in a loop)
4. ❌ Nginx had no healthy backend to forward requests to
5. ❌ Your browser got "Connection refused"

**Why MongoDB connection failed:**
- Docker containers can't reach external IPs from the private Docker network by default
- They need to use service names for internal communication
- The hardcoded IP wasn't being resolved inside the Docker network

---

## 📋 CHECKLIST FOR SUCCESS

After running the fix:

- [ ] All 4 containers running: `docker compose ps`
- [ ] All containers show "Up" status (not restarting)
- [ ] Backend health check works: `curl http://localhost:8000/health`
- [ ] MongoDB logs show it's accepting connections
- [ ] Backend logs show "Connected to MongoDB" (or similar)
- [ ] External test works: `curl http://139.59.82.105:8000/health` (from local machine)
- [ ] Browser shows Hypersend frontend or API response at http://139.59.82.105:8000

---

## 🆘 IF STILL NOT WORKING

**Run diagnostic script:**
```bash
cd /hypersend/Hypersend
bash DIAGNOSE_VPS.sh
```

This shows:
- Service status
- Port usage
- Container logs
- Network configuration
- Recommendations

**Then share the output for deeper debugging.**

---

## 📝 Key Points to Remember

✅ **Use Docker service names** (`mongodb:27017`) for container-to-container communication
✅ **Disable local mongod** service that was failing (exit-code 14)
✅ **MongoDB runs in Docker** - no need for local installation
✅ **Port 27017 exposed** for external access (clients can still connect)
✅ **Environment variable priority** - MONGODB_URI can be overridden in .env
✅ **GitHub has latest fixes** - Always pull before restarting

---

## 📞 Need Help?

If you're still having issues:
1. Run: `bash DIAGNOSE_VPS.sh`
2. Share the output
3. Check README.md Troubleshooting section
4. Review backend logs: `docker compose logs backend`
5. Check MongoDB logs: `docker compose logs mongodb`

---

**Last Updated:** Commit 79c6429
**GitHub Repo:** https://github.com/Mayankvlog/Hypersend.git
