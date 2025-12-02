# 🔧 VPS Deployment Troubleshooting Guide

**Issue:** Backend not responding at http://139.59.82.105:8000

**Status:** Fixed - Configuration corrected ✅

---

## 🔍 Diagnostic Steps (Run on VPS)

### Step 1: Check Docker Services
```bash
# SSH to VPS
ssh root@139.59.82.105

# Navigate to project
cd /hypersend/Hypersend

# Check all containers
docker-compose ps

# Should show:
# NAME                 STATUS
# hypersend_backend    Up X seconds
# hypersend_frontend   Up X seconds
# hypersend_mongodb    Up X seconds (healthy)
```

### Step 2: Check Backend Logs
```bash
# View backend logs (last 50 lines)
docker logs hypersend_backend --tail=50

# View logs in real-time
docker logs -f hypersend_backend

# Look for errors like:
# ❌ "SECRET_KEY must be changed"
# ❌ "CRITICAL: Failed to start"
# ✅ "Uvicorn running on http://0.0.0.0:8000"
```

### Step 3: Verify .env File Configuration
```bash
# Check if .env exists
cat .env | grep -E "SECRET_KEY|MONGO_PASSWORD|DEBUG|VPS_IP"

# Should output:
# SECRET_KEY=72hf2XTyuBXOGVbpgS9iyJKSePUTwLcLQL_DsaC4yqk
# MONGO_PASSWORD=changeme
# DEBUG=False
# VPS_IP=139.59.82.105
```

### Step 4: Test Connectivity Inside Container
```bash
# Connect to backend container
docker exec -it hypersend_backend bash

# Inside container, test if it's listening
curl http://localhost:8000/health

# Or check if port is listening
netstat -tulpn | grep 8000

# Exit container
exit
```

### Step 5: Check Network Configuration
```bash
# View Docker networks
docker network ls

# Inspect hypersend network
docker network inspect hypersend_hypersend_network

# Check if all containers are on the network
docker network inspect hypersend_hypersend_network | grep -A 5 "Containers"
```

### Step 6: Verify MongoDB Connection
```bash
# Check MongoDB logs
docker logs hypersend_mongodb --tail=20

# Connect to MongoDB container
docker exec -it hypersend_mongodb mongosh -u admin -p changeme

# Inside MongoDB shell
show databases
use hypersend
db.stats()
exit
```

---

## 🔧 Common Issues & Fixes

### Issue 1: "Unable to connect" - Backend not responding

**Cause:** Backend container not running or port not exposed

**Fix:**
```bash
# Check container status
docker-compose ps

# If not running, start it
docker-compose up -d backend

# Check logs for errors
docker logs hypersend_backend
```

### Issue 2: "SECRET_KEY must be changed" Error

**Cause:** .env file missing or SECRET_KEY not set

**Fix:**
```bash
# Verify .env exists
ls -la .env

# If missing, create from example
cp .env.example .env

# Verify SECRET_KEY is set
cat .env | grep SECRET_KEY

# Should show:
# SECRET_KEY=72hf2XTyuBXOGVbpgS9iyJKSePUTwLcLQL_DsaC4yqk

# Restart backend
docker-compose restart backend
```

### Issue 3: MongoDB Authentication Failed

**Cause:** MONGO_PASSWORD mismatch between .env and docker-compose.yml

**Fix:**
```bash
# Check .env MONGO_PASSWORD
grep MONGO_PASSWORD .env

# Check if it matches the default
# Should be: changeme

# If different, rebuild MongoDB:
docker-compose down mongodb
docker volume rm hypersend_mongodb_data
docker-compose up -d mongodb

# Wait 30 seconds for MongoDB to initialize
sleep 30

# Restart backend
docker-compose restart backend
```

### Issue 4: Port 8000 Already In Use

**Cause:** Another service using port 8000

**Fix:**
```bash
# Find process on port 8000
netstat -tulpn | grep 8000
lsof -i :8000

# Kill the process
kill -9 <PID>

# Or change port in docker-compose.yml:
# Change: "8000:8000" to "8001:8000"
# Then: docker-compose up -d
```

### Issue 5: Container Exits Immediately

**Cause:** Application crash or configuration error

**Fix:**
```bash
# Check full logs
docker logs hypersend_backend

# Look for specific error messages
docker logs hypersend_backend 2>&1 | grep -i error

# Rebuild and restart
docker-compose down backend
docker-compose pull backend
docker-compose up -d backend
```

---

## ✅ Complete Reset & Redeploy

If nothing else works, do a complete reset:

```bash
# 1. Stop all services
docker-compose down

# 2. Remove volumes (WARNING: deletes data)
docker volume rm hypersend_mongodb_data
docker volume rm hypersend_mongodb_config

# 3. Pull latest images
docker-compose pull

# 4. Start fresh
docker-compose up -d

# 5. Wait for services to be ready
sleep 10

# 6. Check status
docker-compose ps

# 7. Check logs
docker logs hypersend_backend
```

---

## 🧪 Verification Checklist

After deployment, verify everything works:

```bash
# 1. Check container status ✓
docker-compose ps

# 2. Check backend logs ✓
docker logs hypersend_backend | grep -i "uvicorn running"

# 3. Test API endpoint ✓
curl http://localhost:8000/health

# 4. Test from browser ✓
# Visit: http://139.59.82.105:8000/docs

# 5. Check frontend ✓
curl http://localhost:8550

# 6. Monitor logs ✓
docker logs -f hypersend_backend
```

---

## 📊 Key Configuration Details

### What Should Be In .env

```env
# These are the critical values:
VPS_IP=139.59.82.105
MONGO_USER=admin
MONGO_PASSWORD=changeme
SECRET_KEY=72hf2XTyuBXOGVbpgS9iyJKSePUTwLcLQL_DsaC4yqk
DEBUG=False
```

### What docker-compose.yml Does

- Creates MongoDB service with auth enabled
- Creates Backend (FastAPI) service on port 8000
- Creates Frontend (Flet) service on port 8550
- Connects all services on internal network
- Exposes ports to host machine
- Uses environment variables from .env file

### Network Architecture

```
VPS External (139.59.82.105:8000)
          ↓
Docker Host Network
          ↓
Internal Network (172.20.0.0/16)
          ↓
┌─────────────────────────────┐
│ Frontend (8550)             │
│ Backend (8000)              │
│ MongoDB (27017 internal)    │
└─────────────────────────────┘
```

---

## 🚀 Quick Deployment Command

```bash
# One-liner to deploy:
cd /hypersend/Hypersend && \
cp .env.example .env && \
docker-compose down && \
docker-compose pull && \
docker-compose up -d && \
sleep 5 && \
docker-compose ps && \
docker logs hypersend_backend --tail=20
```

---

## 📞 Additional Resources

- **README.md** - Project overview
- **QUICK_DEPLOY.md** - Quick deployment guide
- **deploy-production.sh** - Automated deployment script
- **docker-compose.yml** - Docker configuration

---

## 🎯 Next Steps

1. ✅ Run diagnostic steps above
2. ✅ Check error messages in logs
3. ✅ Apply corresponding fix
4. ✅ Verify with curl command
5. ✅ Test in browser: http://139.59.82.105:8000/docs

If issues persist, share full logs output with all error messages.

---

**Last Updated:** December 2, 2025  
**Version:** 1.0.0  
**Status:** Production Ready
