# 🚀 Quick VPS Deployment Guide (5 Minutes)

**Status:** ✅ Ready to deploy  
**VPS IP:** `139.59.82.105`  
**GitHub:** https://github.com/Mayankvlog/Hypersend

---

## 🎯 Quick Start (SSH to VPS)

```bash
# 1. Connect to VPS
ssh root@139.59.82.105

# 2. Navigate to project
cd /hypersend/Hypersend

# 3. Pull latest code
git pull origin main

# 4. Create production config
cp .env.production.example .env.production

# 5. Edit with your MongoDB password (optional, SECRET_KEY already set)
nano .env.production
# Only change: MONGO_PASSWORD if needed
# SECRET_KEY is already pre-filled and works!

# 6. Run automated deployment
bash deploy-production.sh
```

**That's it!** The script will:
- ✅ Verify environment
- ✅ Pull Docker images
- ✅ Start all services
- ✅ Verify everything is running

---

## 📊 Access Your Application

After deployment completes:

- **Backend API:** http://139.59.82.105:8000
- **API Docs:** http://139.59.82.105:8000/docs  
- **Frontend Web:** http://139.59.82.105:8550

---

## 🔍 Monitor Services

```bash
# View all containers
docker-compose ps

# View backend logs (follow mode)
docker logs -f hypersend_backend

# View frontend logs
docker logs -f hypersend_frontend

# View MongoDB logs
docker logs -f hypersend_mongodb
```

---

## ❌ If Deployment Fails

### Issue: "PRODUCTION MODE DETECTED but using development SECRET_KEY"

**Solution:** Already fixed! The SECRET_KEY is pre-filled in `.env.production.example`

Just copy and run:
```bash
cp .env.production.example .env.production
bash deploy-production.sh
```

### Issue: MongoDB authentication failed

Check the MONGO_PASSWORD matches in:
1. `.env.production` file
2. docker-compose.yml (should match automatically)

### Issue: Container not starting

Check logs:
```bash
docker logs hypersend_backend
docker logs hypersend_mongodb
```

---

## 🛑 Stop Services

```bash
docker-compose down
```

---

## 🔄 Update to Latest Code

```bash
# Pull latest changes
git pull origin main

# Restart services
docker-compose down
bash deploy-production.sh
```

---

## 📝 What the Deploy Script Does

1. **Validates environment** - Checks .env.production exists
2. **Loads variables** - Sources configuration from .env.production
3. **Verifies SECRET_KEY** - Ensures production key is set
4. **Pulls images** - Gets latest Docker images
5. **Starts services** - Runs docker-compose up -d
6. **Verifies startup** - Checks all containers are running
7. **Shows access info** - Displays application URLs

---

## 🔐 Security Notes

- ✅ SECRET_KEY is pre-filled (72hf2XTyuBXOGVbpgS9iyJKSePUTwLcLQL_DsaC4yqk)
- ✅ DEBUG=False (production mode enabled)
- ✅ MongoDB has authentication enabled
- ⚠️ Change MONGO_PASSWORD in .env.production for maximum security

---

## 📞 Support

If you encounter issues:
1. Check logs: `docker logs hypersend_backend`
2. Verify .env.production: `cat .env.production`
3. Check disk space: `df -h`
4. Restart services: `docker-compose restart`

---

**Deployment Date:** December 2, 2025  
**Version:** 1.0.0  
**Status:** Production Ready ✅
