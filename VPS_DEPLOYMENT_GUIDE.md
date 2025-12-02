# 🚀 Zaply - VPS Deployment Guide (Docker)

## Quick Start (5 minutes)

```bash
# SSH into your VPS
ssh root@139.59.82.105

# Navigate to project
cd /hypersend/Hypersend

# Create production environment file
cp .env.production.example .env.production

# Edit with your values
nano .env.production
# Change:
# - SECRET_KEY=<your-generated-key>
# - MONGO_PASSWORD=<your-secure-password>
# - VPS_IP=139.59.82.105

# Load environment
source .env.production

# Pull latest images and start
docker-compose pull
docker-compose up -d

# Verify
docker-compose ps
docker logs hypersend_backend
```

---

## Step-by-Step Deployment

### 1. Generate Secure SECRET_KEY

On your VPS:
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

Copy the output. Example: `o7-xK8pL9m0n1Q2r3S4t5U6v7W8x9Y0z1A2b3C4d`

### 2. Create Production Environment File

```bash
cd /hypersend/Hypersend
cp .env.production.example .env.production
nano .env.production
```

Update these critical values:

```env
# Line 7: Generated SECRET_KEY
SECRET_KEY=o7-xK8pL9m0n1Q2r3S4t5U6v7W8x9Y0z1A2b3C4d

# Line 5: MongoDB secure password
MONGO_PASSWORD=MySecurePass123!@#

# Line 8: Debug mode OFF
DEBUG=False

# Line 13: Your VPS IP
VPS_IP=139.59.82.105
```

Save: `Ctrl+X`, `Y`, `Enter`

### 3. Load Environment Variables

```bash
source .env.production
echo $SECRET_KEY  # Verify it loaded
```

### 4. Pull Latest Docker Images

```bash
docker-compose pull
```

Output should show:
```
Pulling backend ... done
Pulling frontend ... done
Pulling mongodb ... done
```

### 5. Start Services

```bash
docker-compose up -d
```

### 6. Verify Everything Started

```bash
# Check all containers running
docker-compose ps

# Should show:
# NAME                      STATUS
# hypersend_backend         Up X seconds
# hypersend_frontend        Up X seconds
# hypersend_mongodb         Up X seconds (healthy)
```

### 7. Check Backend Logs

```bash
docker logs hypersend_backend -f
```

✅ **SUCCESS** - You should see:
```
[START] Zaply API starting on 0.0.0.0:8000
[START] Environment: PRODUCTION
[DB] Initializing MongoDB...
[MONGO_INIT] ✅ MongoDB initialization complete
[INFO] ✅ Production validations passed
INFO:     Uvicorn running on http://0.0.0.0:8000
```

❌ **ERROR** - If you see:
```
ValueError: CRITICAL: SECRET_KEY must be changed in production!
```

**Fix:**
```bash
# Regenerate and update .env.production
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
# Copy output to .env.production SECRET_KEY=...

# Restart
source .env.production
docker-compose restart backend
```

---

## Access the Application

### API Endpoints

- **Swagger UI (Interactive Docs):** http://139.59.82.105:8000/docs
- **ReDoc (API Reference):** http://139.59.82.105:8000/redoc
- **Backend Health:** http://139.59.82.105:8000/health

### Frontend

- **Web App:** http://139.59.82.105:8550

---

## Monitoring & Troubleshooting

### View All Logs

```bash
# Backend logs
docker logs hypersend_backend -f

# Frontend logs
docker logs hypersend_frontend -f

# MongoDB logs
docker logs hypersend_mongodb -f
```

### Check Container Status

```bash
# Detailed info
docker-compose ps -a

# Resource usage
docker stats

# Check specific service
docker inspect hypersend_backend
```

### Common Issues

#### Issue: "SECRET_KEY must be changed in production"

```bash
# Check if environment variable is loaded
echo $SECRET_KEY

# If empty, load it again
source .env.production
echo $SECRET_KEY

# Restart container
docker-compose restart backend
docker logs hypersend_backend -f
```

#### Issue: "MongoDB Connection refused"

```bash
# Check MongoDB container
docker logs hypersend_mongodb

# Verify credentials match docker-compose.yml
grep MONGO_PASSWORD .env.production

# Rebuild MongoDB
docker-compose down mongodb
docker volume rm hypersend_mongodb_data
docker-compose up -d mongodb
```

#### Issue: "Port 8000 already in use"

```bash
# Kill process on port 8000
sudo lsof -i :8000
sudo kill -9 <PID>

# Or change port in docker-compose.yml
# ports:
#   - "8001:8000"  # Changed from 8000:8000
```

#### Issue: Frontend can't reach backend

```bash
# Check both are on same network
docker network inspect hypersend_hypersend_network

# Verify API_BASE_URL in docker-compose.yml
grep API_BASE_URL docker-compose.yml

# Should be: http://backend:8000 (internal) or
# http://139.59.82.105:8000 (external)
```

---

## Production Best Practices

### ✅ Security Checklist

- [ ] SECRET_KEY is unique and securely generated
- [ ] DEBUG=False in production
- [ ] MONGO_PASSWORD is strong (12+ chars, mixed case, symbols)
- [ ] .env.production is in .gitignore
- [ ] Using HTTPS (nginx proxy recommended)
- [ ] Database credentials are not hardcoded
- [ ] Regular backups of MongoDB data
- [ ] Monitor disk space (40GB max per file)

### 📊 Recommended Additions

#### 1. Nginx Reverse Proxy (HTTPS)

```bash
# Install nginx
sudo apt-get install nginx

# Create config
sudo nano /etc/nginx/sites-available/zaply

# Add to config:
# server {
#     listen 443 ssl http2;
#     server_name yourdomain.com;
#     ssl_certificate /path/to/cert.pem;
#     ssl_certificate_key /path/to/key.pem;
#     
#     location / {
#         proxy_pass http://localhost:8000;
#         proxy_set_header Host $host;
#     }
# }

sudo systemctl restart nginx
```

#### 2. Let's Encrypt SSL (Free HTTPS)

```bash
# Install certbot
sudo apt-get install certbot python3-certbot-nginx

# Generate certificate
sudo certbot certonly --nginx -d yourdomain.com

# Auto-renew
sudo systemctl enable certbot.timer
```

#### 3. Backup MongoDB

```bash
# Create backup script
cat > /hypersend/backup-mongo.sh << 'EOF'
#!/bin/bash
docker exec hypersend_mongodb mongodump \
  --authenticationDatabase admin \
  -u admin \
  -p $MONGO_PASSWORD \
  --out /backups/$(date +%Y%m%d_%H%M%S)
EOF

chmod +x /hypersend/backup-mongo.sh

# Schedule daily at 2 AM
(crontab -l 2>/dev/null; echo "0 2 * * * /hypersend/backup-mongo.sh") | crontab -
```

#### 4. Monitoring & Alerts

```bash
# Install monitoring
docker run -d \
  --name watchtower \
  -v /var/run/docker.sock:/var/run/docker.sock \
  containrrr/watchtower \
  --cleanup --poll-every-hours 6

# Auto-updates containers from registry
```

---

## Updating the Application

### Pull Latest Changes

```bash
# Navigate to project
cd /hypersend/Hypersend

# Pull from GitHub
git pull origin main

# Load environment
source .env.production

# Pull latest images
docker-compose pull

# Restart services
docker-compose down
docker-compose up -d

# Monitor startup
docker logs hypersend_backend -f
```

### Rollback if Issues

```bash
# Stop current version
docker-compose down

# Use previous image tag
docker-compose pull stable
docker-compose up -d

# Check logs
docker logs hypersend_backend
```

---

## Performance Tuning

### Database Optimization

```bash
# Connect to MongoDB
docker exec -it hypersend_mongodb mongosh -u admin -p $MONGO_PASSWORD

# Create indexes
db.messages.createIndex({ userId: 1, createdAt: -1 })
db.files.createIndex({ userId: 1, uploadedAt: -1 })

# Check indexes
db.messages.getIndexes()
```

### Resource Limits

Edit `docker-compose.yml`:

```yaml
services:
  backend:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '1'
          memory: 1G
```

### API Rate Limiting

In `.env.production`:

```env
RATE_LIMIT_PER_USER=100      # Requests per window
RATE_LIMIT_WINDOW_SECONDS=60 # Time window
```

---

## Maintenance Commands

### View System Status

```bash
# All containers
docker-compose ps

# Resource usage
docker stats

# Disk space
df -h

# Memory usage
free -h
```

### Clean Up

```bash
# Remove unused images
docker image prune -a

# Remove unused volumes
docker volume prune

# Remove unused networks
docker network prune

# Complete cleanup (warning: removes untagged images)
docker system prune -a
```

### Restart Services

```bash
# Restart specific service
docker-compose restart backend

# Restart all services
docker-compose restart

# Full restart with rebuild
docker-compose down
docker-compose up -d --build
```

---

## Support & Documentation

- **API Docs:** http://139.59.82.105:8000/docs
- **GitHub:** https://github.com/Mayankvlog/Hypersend
- **Local Backend Guide:** BACKEND_SETUP_GUIDE.md
- **Fix Guide:** BACKEND_FIX_GUIDE.md

---

## Environment Variables Reference

| Variable | Default | Purpose |
|----------|---------|---------|
| `SECRET_KEY` | dev-secret-key... | JWT signing (CHANGE FOR PRODUCTION) |
| `DEBUG` | False | Enable debug mode |
| `MONGO_USER` | admin | MongoDB username |
| `MONGO_PASSWORD` | changeme | MongoDB password |
| `MONGODB_URI` | mongodb://... | Database connection string |
| `API_BASE_URL` | http://localhost:8000 | Public API URL |
| `VPS_IP` | localhost | Server IP/domain |
| `RATE_LIMIT_PER_USER` | 100 | Requests per window |
| `MAX_FILE_SIZE_BYTES` | 42949672960 | Max file size (40GB) |

---

**Last Updated:** December 2, 2025  
**Version:** 1.0.0  
**Status:** Production Ready
