# Zaply Production Deployment Guide

## Quick Start (2 Steps)

### Step 1: SSH into VPS
```bash
ssh root@139.59.82.105
```

### Step 2: Deploy Complete Stack
```bash
cd /hypersend/Hypersend
cp .env.example .env
docker-compose pull
docker-compose up -d
sleep 10
docker-compose ps
```

## Verify Deployment

### Check All Services Running
```bash
docker-compose ps
# Expected: All 4 services "Up"
# - nginx
# - backend  
# - frontend
# - mongodb
```

### Test Health Endpoints

**Nginx reverse proxy:**
```bash
curl http://139.59.82.105/health
# Expected: ok
```

**Backend API (via nginx):**
```bash
curl http://139.59.82.105/api/v1/health
# Expected: {"status":"ok"} or similar
```

**Frontend (via nginx):**
```bash
curl -L http://139.59.82.105
# Expected: HTML response from Flet frontend
```

**Direct access (if needed):**
```bash
curl http://139.59.82.105:8000/health   # Backend direct
curl http://139.59.82.105:8550          # Frontend direct
```

## Access Your App

| Component | URL |
|-----------|-----|
| **Frontend App** | http://139.59.82.105 |
| **API Docs** | http://139.59.82.105/api/v1/docs |
| **Backend API** | http://139.59.82.105/api/v1 |

## Monitoring

### View Live Logs
```bash
docker logs -f hypersend_nginx    # Nginx access logs
docker logs -f hypersend_backend  # Backend API logs
docker logs -f hypersend_frontend # Frontend logs
docker logs -f hypersend_mongodb  # Database logs
```

### Check System Resources
```bash
docker stats

# Or individual service
docker stats hypersend_nginx
```

### Restart Services
```bash
# Restart all
docker-compose restart

# Restart specific service
docker-compose restart nginx
docker-compose restart backend
```

## Troubleshooting

### Issue: Services won't start

**Check logs:**
```bash
docker-compose logs

# Or specific service
docker-compose logs nginx
docker-compose logs backend
```

**Common fixes:**
```bash
# Restart from scratch
docker-compose down -v
docker-compose pull
docker-compose up -d

# Check .env file
cat .env
```

### Issue: 502 Bad Gateway

**Cause:** Backend/Frontend not responding

**Fix:**
```bash
docker-compose restart backend frontend
docker logs hypersend_nginx | tail -20
```

### Issue: Can't connect to API

**Check backend port:**
```bash
docker ps | grep backend
# Should show: 8000:8000

# Test connection
curl http://127.0.0.1:8000/health
```

### Issue: MongoDB authentication failed

**Check credentials in .env:**
```bash
grep MONGO .env
# Should have:
# MONGO_USER=admin
# MONGO_PASSWORD=changeme  (or your custom password)
```

**Verify MongoDB:**
```bash
docker exec hypersend_mongodb mongosh -u admin -p changeme --authenticationDatabase admin
```

## File Locations

```
/hypersend/Hypersend/
├── nginx.conf              # Nginx reverse proxy config
├── docker-compose.yml      # Service orchestration
├── .env                    # Environment variables (created from .env.example)
├── .env.example            # Template with defaults
├── backend/                # FastAPI backend
├── frontend/               # Flet web frontend
├── data/                   # Volume mount for files
└── NGINX_SETUP.md          # Detailed nginx documentation
```

## Database Management

### Access MongoDB CLI
```bash
docker exec -it hypersend_mongodb mongosh -u admin -p changeme --authenticationDatabase admin
```

### Backup Database
```bash
docker exec hypersend_mongodb mongodump --uri mongodb://admin:changeme@localhost:27017/hypersend --out /data/backup

# Or
docker exec hypersend_mongodb mongodump --username admin --password changeme --authenticationDatabase admin --db hypersend --out /data/backup
```

### Restore Database
```bash
docker exec hypersend_mongodb mongorestore --username admin --password changeme --authenticationDatabase admin /data/backup
```

## Maintenance

### Update Application
```bash
cd /hypersend/Hypersend
git pull origin main
docker-compose pull
docker-compose restart
```

### Clean Up Old Images/Containers
```bash
docker system prune -a  # WARNING: Removes all unused images

# Or be selective
docker system prune      # Removes only stopped containers
```

### Check Disk Space
```bash
df -h
du -sh /hypersend/Hypersend/data
```

## Configuration Changes

To update environment variables:

1. **Edit .env file:**
   ```bash
   nano .env
   ```

2. **Restart affected services:**
   ```bash
   docker-compose up -d
   ```

3. **Or specific service:**
   ```bash
   docker-compose restart backend  # If you changed backend env vars
   ```

## Security Hardening (Production)

### 1. Update MongoDB Password
```bash
# Edit .env
MONGO_PASSWORD=your-strong-password-here

# Restart MongoDB and Backend
docker-compose restart mongodb backend
```

### 2. Update JWT Secret Key
```bash
# Generate new key
python3 -c "import secrets; print(secrets.token_urlsafe(32))"

# Add to .env
SECRET_KEY=<paste-generated-key>

# Restart backend
docker-compose restart backend
```

### 3. Set DEBUG=False
```bash
# Edit .env
DEBUG=False

# Restart backend
docker-compose restart backend
```

### 4. Enable HTTPS (SSL/TLS)
See NGINX_SETUP.md for Let's Encrypt setup

## Performance Optimization

### Increase File Upload Timeout (if needed)
Edit nginx.conf:
```nginx
proxy_read_timeout 7200s;  # 2 hours instead of 1
```

### Enable Redis Caching (advanced)
Add to docker-compose.yml and configure backend

### Horizontal Scaling
To run multiple backend instances:
```nginx
upstream backend_service {
    server backend-1:8000;
    server backend-2:8000;
    server backend-3:8000;
}
```

## Support & Documentation

- **Nginx Setup Details:** NGINX_SETUP.md
- **Backend Configuration:** backend/config.py
- **Frontend Configuration:** frontend/app.py
- **API Documentation:** http://139.59.82.105/api/v1/docs (Swagger UI)
- **Source Code:** https://github.com/Mayankvlog/Hypersend

---

**Status:** ✅ Production Ready

All services configured for:
- ✅ High availability with reverse proxy
- ✅ Large file transfers (40GB support)
- ✅ Rate limiting and security
- ✅ WebSocket support for real-time features
- ✅ Gzip compression
- ✅ Health monitoring
- ✅ Easy maintenance and scaling
