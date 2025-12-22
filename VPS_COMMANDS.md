# VPS Deployment Command Reference

## Copy-Paste Ready Commands for DigitalOcean Ubuntu VPS

---

## Phase 1: Prerequisites (Run Once)

```bash
# Update system
sudo apt-get update && sudo apt-get upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
newgrp docker

# Verify Docker Compose
docker compose version

# Install Git and utilities
sudo apt-get install -y git curl openssl certbot python3-certbot-nginx
```

---

## Phase 2: Get Let's Encrypt Certificate (If Not Already Done)

```bash
# Check if cert exists
ls -la /etc/letsencrypt/live/zaply.in.net/

# If NOT found, generate certificate
sudo certbot certonly --standalone -d zaply.in.net

# Verify cert was created
sudo ls -la /etc/letsencrypt/live/zaply.in.net/
```

---

## Phase 3: Clone & Configure (Main Deployment)

```bash
# Navigate to home and create project directory
cd /root
mkdir -p hypersend
cd hypersend

# Clone the repository
git clone https://github.com/Mayankvlog/Hypersend.git .

# Verify files
ls -la
# Should show: docker-compose.yml, nginx.conf, backend/, frontend/, etc.

# Create .env file with strong passwords
cat > .env << 'EOF'
MONGO_USER=hypersend
MONGO_PASSWORD=YOUR_STRONG_PASSWORD_HERE
SECRET_KEY=YOUR_STRONG_SECRET_HERE
API_BASE_URL=https://zaply.in.net/api/v1
CORS_ORIGINS=https://zaply.in.net,http://zaply.in.net
DEBUG=False
EOF

# Edit .env to set REAL passwords (DO NOT SKIP THIS!)
nano .env

# Verify .env looks good
cat .env

# Verify DNS is resolving
nslookup zaply.in.net
# Should return your VPS IP address

# Verify Let's Encrypt certs exist and are accessible
sudo ls -la /etc/letsencrypt/live/zaply.in.net/
# Should show: fullchain.pem, privkey.pem, cert.pem, chain.pem
```

---

## Phase 4: Deploy Services

```bash
# Make sure you're in /root/hypersend
pwd
# Should output: /root/hypersend

# Build and start all services (takes 5-10 minutes)
docker compose up -d --build

# Monitor the build (watch for "healthy" status)
docker compose logs -f

# Once all services show "healthy" or no more output, press Ctrl+C

# Check final service status
docker compose ps
```

**Expected Output:**
```
NAME                 IMAGE                              STATUS
hypersend_nginx      nginx:alpine                       Up (healthy)
hypersend_backend    hypersend-backend                  Up (healthy)
hypersend_frontend   hypersend-frontend                 Up (healthy)
hypersend_mongodb    mongo:7.0                          Up (healthy)
```

---

## Phase 5: Verify Deployment (Test Everything)

```bash
# Test 1: Check service health
docker compose ps

# Test 2: HTTP to HTTPS redirect
curl -i http://zaply.in.net/health
# Should see: 301 Moved Permanently

# Test 3: HTTPS health endpoint
curl -i https://zaply.in.net/health
# Should see: 200 healthy

# Test 4: Backend API health
curl -i https://zaply.in.net/api/v1/health
# Should see: 200 {"status":"healthy"}

# Test 5: Frontend loads (get first 20 lines)
curl -s https://zaply.in.net/ | head -20
# Should contain HTML with Flutter app

# Test 6: CORS preflight request
curl -i -X OPTIONS https://zaply.in.net/api/v1/chats/ \
  -H "Origin: https://zaply.in.net" \
  -H "Access-Control-Request-Method: GET"
# Should see: 204 with Access-Control-Allow-* headers

# Test 7: Check MongoDB connection (from backend logs)
docker compose logs backend | grep -i "mongodb\|connected\|healthy"
# Should show success messages

# Test 8: View full backend startup logs
docker compose logs backend | head -50
# Should show successful initialization
```

---

## Phase 6: Manual Testing (Browser)

```bash
# Open browser and visit:
https://zaply.in.net

# You should see:
# - Flutter Material3 UI loading
# - Login form or app interface (depending on setup)

# Open DevTools (F12) in browser and go to Network tab
# Try to login or navigate
# Verify:
# - All API calls go to https://zaply.in.net/api/v1/*
# - No NS_ERROR or connection failures
# - Responses are 200 OK (or expected status codes)
# - Authorization header: Bearer <token> is present
```

---

## Ongoing Maintenance Commands

### View Logs

```bash
# Real-time logs (all services)
docker compose logs -f --tail=50

# Specific service logs
docker compose logs backend -f --tail=100
docker compose logs frontend -f --tail=100
docker compose logs mongodb -f --tail=100
docker compose logs nginx -f --tail=100

# Search for errors
docker compose logs | grep -i "error\|failed\|exception"
```

### Update Code

```bash
# Pull latest changes from GitHub
git pull origin main

# Rebuild and restart services
docker compose up -d --build

# Monitor restart
docker compose logs -f --tail=100
```

### Backup MongoDB

```bash
# Create backup with timestamp
docker compose exec -T mongodb mongodump \
  -u hypersend \
  -p "$MONGO_PASSWORD" \
  --authenticationDatabase admin \
  -o /data/backup_$(date +%Y%m%d_%H%M%S)

# List backups
docker compose exec mongodb ls -la /data/

# Restore from backup (if needed)
docker compose exec -T mongodb mongorestore \
  -u hypersend \
  -p "$MONGO_PASSWORD" \
  --authenticationDatabase admin \
  /data/backup_20251222_120000
```

### Renew SSL Certificate

```bash
# Manual renewal (auto-renews daily, but force if needed)
sudo certbot renew --force-renewal

# Verify new cert validity
sudo openssl x509 \
  -in /etc/letsencrypt/live/zaply.in.net/fullchain.pem \
  -text -noout | grep "Not After"

# Nginx automatically uses new cert (no restart needed)
```

### Stop/Start Services

```bash
# Stop all services
docker compose down

# Start all services
docker compose up -d

# Restart specific service
docker compose restart backend
docker compose restart nginx
docker compose restart mongodb
docker compose restart frontend

# Remove all containers (careful!)
docker compose down -v
```

### Database Queries

```bash
# Connect to MongoDB shell
docker compose exec mongodb mongosh \
  -u hypersend \
  -p "YOUR_MONGO_PASSWORD" \
  --authenticationDatabase admin

# In mongosh shell:
# > use hypersend
# > db.users.find().pretty()
# > db.chats.find().pretty()
# > exit
```

### Check Disk Usage

```bash
# Overall disk usage
df -h

# Docker disk usage
docker system df

# Clean up unused images/containers
docker system prune -a

# Remove old logs
docker compose logs --timestamps | head -0 > /dev/null
```

---

## Troubleshooting Commands

### If Services Won't Start

```bash
# Check logs
docker compose logs 2>&1 | tail -100

# Check specific service
docker compose logs backend | tail -50

# Stop everything and check Docker daemon
docker compose down
systemctl status docker

# Verify Docker is running
docker ps

# Check system resources
free -h  # RAM
df -h    # Disk space
```

### If MongoDB Won't Connect

```bash
# Check MongoDB is running
docker compose logs mongodb | tail -30

# Test connection manually
docker compose exec mongodb mongosh \
  -u hypersend \
  -p "YOUR_MONGO_PASSWORD" \
  --authenticationDatabase admin \
  --eval "db.adminCommand('ping')"

# Check MongoDB logs for auth errors
docker compose logs mongodb | grep -i "auth\|error"

# Verify MONGODB_URI is correct
docker compose exec backend env | grep MONGODB_URI
```

### If API Returns 401/403

```bash
# Check SECRET_KEY is set and > 32 chars
echo $SECRET_KEY | wc -c

# Check backend logs for auth errors
docker compose logs backend | grep -i "auth\|401\|403"

# Test with valid token
TOKEN="your_bearer_token"
curl -v -H "Authorization: Bearer $TOKEN" \
  https://zaply.in.net/api/v1/chats/
```

### If Frontend Shows Blank Page

```bash
# Check frontend logs
docker compose logs frontend | tail -50

# Test frontend is running
docker compose exec frontend wget -q -O - http://localhost/health

# Check Nginx is proxying correctly
docker compose logs nginx | tail -30

# Verify API base URL is correct in frontend config
# (Should be: https://zaply.in.net/api/v1)
```

### If Port 80/443 Already in Use

```bash
# Check what's using ports
sudo lsof -i :80 -i :443

# Stop other services
sudo systemctl stop nginx
sudo systemctl stop apache2

# Or change Docker Compose ports (not recommended for production)
# Edit docker-compose.yml: ports: "8080:80", "8443:443"
```

---

## Emergency Commands

### Force Restart Everything

```bash
# Stop all services
docker compose down

# Remove containers and volumes
docker compose down -v

# Clean up Docker system
docker system prune -f

# Rebuild everything
docker compose up -d --build

# Monitor startup
docker compose logs -f --tail=100
```

### View Database

```bash
# Connect to MongoDB
docker compose exec mongodb mongosh \
  -u hypersend \
  -p "$MONGO_PASSWORD" \
  --authenticationDatabase admin

# List databases
> show dbs

# Use hypersend database
> use hypersend

# List collections
> show collections

# View sample data
> db.users.findOne()
> db.chats.findOne()

# Exit
> exit
```

### Reset Everything (⚠️ Careful!)

```bash
# This will DELETE all data! Only do this if you want to start fresh.

# Stop services
docker compose down

# Remove all volumes (deletes MongoDB data)
docker volume rm hypersend_mongodb_data hypersend_mongodb_config

# Remove all images
docker image prune -a -f

# Remove .env file (to set new passwords)
rm .env

# Start fresh
docker compose up -d --build
```

---

## Security Checks

```bash
# Verify .env has strong passwords
cat .env | grep PASSWORD
# Should show random 32+ char values

# Verify DEBUG is False
cat .env | grep DEBUG
# Should show: DEBUG=False

# Check no secrets in logs
docker compose logs | grep -i "password\|secret"
# Should show nothing (or only redacted values)

# Verify Let's Encrypt cert validity
sudo openssl x509 \
  -in /etc/letsencrypt/live/zaply.in.net/fullchain.pem \
  -noout -dates
# Check "Not After" date is in the future

# Verify .env is in .gitignore
cat .gitignore | grep ".env"
```

---

## Quick Status Check Script

```bash
#!/bin/bash
echo "=== Zaply Production Status ==="
echo
echo "Service Health:"
docker compose ps
echo
echo "Recent Errors:"
docker compose logs --tail=20 | grep -i "error\|exception" || echo "No recent errors"
echo
echo "MongoDB Status:"
docker compose exec -T mongodb mongosh -u hypersend -p "$MONGO_PASSWORD" \
  --authenticationDatabase admin --eval "db.adminCommand('ping')" 2>/dev/null || echo "MongoDB connection failed"
echo
echo "Disk Usage:"
df -h | grep -E "^/|Filesystem"
echo
echo "Docker Disk:"
docker system df | head -5
echo
echo "Certificate Valid Until:"
sudo openssl x509 -in /etc/letsencrypt/live/zaply.in.net/fullchain.pem \
  -noout -dates | grep "After"

# Save as check_status.sh
# Run with: bash check_status.sh
```

---

## URL Reference

- **App:** https://zaply.in.net
- **API Health:** https://zaply.in.net/api/v1/health
- **HTTP Health:** http://zaply.in.net/health (will redirect to HTTPS)

---

## Emergency Contact

If deployment fails:

1. Check logs: `docker compose logs | tail -100`
2. Check specific service: `docker compose logs backend | tail -50`
3. Verify DNS: `nslookup zaply.in.net`
4. Verify certs: `sudo ls -la /etc/letsencrypt/live/zaply.in.net/`
5. Check .env: `cat .env`
6. Review DEPLOYMENT_GUIDE.md for troubleshooting

---

**Last Updated:** December 22, 2025  
**Repository:** https://github.com/Mayankvlog/Hypersend
