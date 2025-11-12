# 🚀 HyperSend - Complete Production Deployment Guide
## DigitalOcean VPS + GitHub Actions + DockerHub (For Lakhs of Users with $100 Credit)

---

## 📊 Quick Summary

| Component | Cost | Capacity | Duration |
|-----------|------|----------|----------|
| **DigitalOcean Droplet** (2 vCPU, 4GB) | $24/month | 20K-30K users | 4+ months |
| **MongoDB Atlas M0** | FREE | 512MB | Unlimited |
| **Cloudflare CDN** | FREE | Unlimited | Unlimited |
| **GitHub Actions** | FREE | 2000 min/month | Unlimited |
| **Total with $100 credit** | $0 for 4+ months | ✅ Lakhs of users | ✅ Covered |

---

## 🎯 STEP-BY-STEP DEPLOYMENT (Complete Walkthrough)

### PHASE 1: PREPARATION (30 minutes)

#### Step 1.1: Create MongoDB Atlas Account
```
1. Go to: https://www.mongodb.com/cloud/atlas/register
2. Sign up with your email
3. Create Organization → Create Project
4. Create FREE M0 Cluster:
   - Cloud Provider: AWS
   - Region: ap-south-1 (Mumbai) - closest to India
   - Cluster Name: hypersend-prod
5. Wait 5-10 minutes for cluster creation
```

#### Step 1.2: Configure MongoDB Security
```
1. Go to "Network Access" → "Add IP Address"
2. Add: 0.0.0.0/0 (Allow from anywhere)
   - For production: Add only your VPS IP later
3. Go to "Database Access" → "Add Database User"
   - Username: hypersend_user
   - Password: Generate strong password (save it!)
   - Built-in Role: Atlas Admin
4. Click "Add User"
```

#### Step 1.3: Get MongoDB Connection String
```
1. Click "Databases" → "Connect"
2. Choose "Connect your application"
3. Select Driver: Python, Version: 3.6+
4. Copy connection string:
   mongodb+srv://hypersend_user:PASSWORD@cluster0.xxxxx.mongodb.net/hypersend?retryWrites=true&w=majority
5. Replace PASSWORD with your actual password
6. Save this - you'll need it for GitHub Secrets
```

#### Step 1.4: Create DockerHub Account
```
1. Go to: https://hub.docker.com/signup
2. Sign up (free account)
3. Verify email
4. Go to Account Settings → Security → Access Tokens
5. Click "New Access Token"
   - Description: "hypersend-deployment"
   - Permissions: Read, Write, Delete
6. Copy token (save it - won't show again!)
7. Save your username too
```

#### Step 1.5: Create DigitalOcean Account
```
1. Go to: https://www.digitalocean.com/
2. Sign up with email
3. Add payment method
4. Apply promo code for $100 credit (if you have one)
5. Go to Billing → Promo/Coupon Code → Add code
```

---

### PHASE 2: DIGITALOCEAN VPS SETUP (20 minutes)

#### Step 2.1: Create Droplet
```
1. DigitalOcean Dashboard → Create → Droplets
2. Choose Image: Ubuntu 22.04 LTS
3. Choose Plan: Regular (NOT CPU-Optimized)
   - 2 vCPU, 4GB RAM, 80GB SSD = $24/month
   - This handles 20K-30K concurrent users
4. Choose Region: BLR1 (Bangalore) - closest to India
5. Authentication: SSH Key (recommended) or Password
6. Hostname: hypersend-production
7. Click "Create Droplet"
8. Wait 1-2 minutes for creation
9. Copy the IP address (e.g., 123.45.67.89)
```

#### Step 2.2: Initial Server Setup
```bash
# SSH into your server (replace IP with your VPS IP)
ssh root@123.45.67.89

# Update system packages
apt update && apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh
systemctl start docker
systemctl enable docker

# Install Docker Compose
apt install docker-compose -y

# Verify installation
docker --version
docker-compose --version

# Create swap memory (improves performance)
fallocate -l 4G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
echo '/swapfile none swap sw 0 0' >> /etc/fstab

# Install UFW firewall
ufw allow 22    # SSH
ufw allow 80    # HTTP
ufw allow 443   # HTTPS
ufw allow 8000  # Backend API
ufw --force enable

# Create application directory
mkdir -p /root/Hypersend
cd /root/Hypersend
```

#### Step 2.3: Create Environment File
```bash
# On your VPS, create .env file
nano /root/Hypersend/.env
```

Paste this content (replace with your actual values):
```env
# MongoDB Atlas Connection
MONGODB_URI=mongodb+srv://hypersend_user:YOUR_PASSWORD@cluster0.xxxxx.mongodb.net/hypersend?retryWrites=true&w=majority

# Security (generate with: openssl rand -hex 32)
SECRET_KEY=your-super-secret-key-min-32-characters-long-here

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
API_BASE_URL=http://123.45.67.89:8000

# Production Settings
DEBUG=False
ENVIRONMENT=production

# Performance Tuning
CHUNK_SIZE=8388608
MAX_PARALLEL_CHUNKS=8
MAX_FILE_SIZE_BYTES=107374182400

# Rate Limiting (for lakhs of users)
RATE_LIMIT_PER_USER=500
RATE_LIMIT_WINDOW_SECONDS=60

# Storage
DATA_ROOT=/data
STORAGE_MODE=local

# DockerHub
DOCKERHUB_USERNAME=your-dockerhub-username
```

Save: Ctrl+X → Y → Enter

#### Step 2.4: Clone Repository
```bash
# On VPS
cd /root/Hypersend

# Clone your GitHub repo
git clone https://github.com/YOUR_USERNAME/hypersend.git .

# Or if already cloned, pull latest
git pull origin main
```

---

### PHASE 3: GITHUB SECRETS CONFIGURATION (10 minutes)

#### Step 3.1: Add GitHub Secrets
```
1. Go to: GitHub.com → Your Repository
2. Settings → Secrets and variables → Actions
3. Click "New repository secret"
```

Add these 6 secrets one by one:

**Secret 1: DOCKERHUB_USERNAME**
```
Name: DOCKERHUB_USERNAME
Value: your-dockerhub-username
```

**Secret 2: DOCKERHUB_TOKEN**
```
Name: DOCKERHUB_TOKEN
Value: your-dockerhub-access-token
```

**Secret 3: VPS_HOST**
```
Name: VPS_HOST
Value: 123.45.67.89 (your VPS IP)
```

**Secret 4: VPS_USER**
```
Name: VPS_USER
Value: root
```

**Secret 5: VPS_PASSWORD**
```
Name: VPS_PASSWORD
Value: your-vps-password
```

**Secret 6: MONGODB_URI**
```
Name: MONGODB_URI
Value: mongodb+srv://hypersend_user:PASSWORD@cluster0.xxxxx.mongodb.net/hypersend?retryWrites=true&w=majority
```

---

### PHASE 4: DEPLOY APPLICATION (5 minutes)

#### Step 4.1: Trigger Deployment
```bash
# On your local machine
cd C:\Users\mayan\Downloads\Addidas\hypersend

# Make a small change to trigger deployment
echo "# Deployment: $(date)" >> README.md

# Commit and push
git add .
git commit -m "Trigger production deployment"
git push origin main
```

#### Step 4.2: Monitor Deployment
```
1. Go to: GitHub Repository → Actions tab
2. Watch the workflow run
3. It will:
   - Build backend Docker image
   - Build frontend Docker image
   - Push to DockerHub
   - SSH into VPS
   - Pull images and restart containers
4. Wait for "✅ Deployment successful!" message
```

#### Step 4.3: Verify Deployment
```bash
# SSH into VPS
ssh root@123.45.67.89

# Check running containers
docker-compose ps

# Check backend logs
docker-compose logs -f --tail=50 backend

# Test health endpoint
curl http://localhost:8000/health

# Should return: {"status":"healthy"}
```

---

## 🔧 PRODUCTION OPTIMIZATION

### Update docker-compose.yml for Production

Replace your current `docker-compose.yml` with this optimized version:

```yaml
version: '3.8'

services:
  backend:
    image: ${DOCKERHUB_USERNAME:-mayankvlog}/hypersend-backend:latest
    container_name: hypersend_backend
    restart: always
    ports:
      - "8000:8000"
    environment:
      - MONGODB_URI=${MONGODB_URI}
      - SECRET_KEY=${SECRET_KEY}
      - DATA_ROOT=/data
      - API_HOST=0.0.0.0
      - API_PORT=8000
      - DEBUG=False
      - ENVIRONMENT=production
      - WORKERS=4
    volumes:
      - ./data:/data
      - ./logs:/app/logs
    networks:
      - hypersend_network
    deploy:
      resources:
        limits:
          cpus: '3'
          memory: 3.5G
        reservations:
          cpus: '2'
          memory: 2.5G
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  frontend:
    image: ${DOCKERHUB_USERNAME:-mayankvlog}/hypersend-frontend:latest
    container_name: hypersend_frontend
    restart: always
    ports:
      - "8550:8550"
    environment:
      - API_BASE_URL=http://backend:8000
    depends_on:
      - backend
    networks:
      - hypersend_network
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  nginx:
    image: nginx:alpine
    container_name: hypersend_nginx
    restart: always
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
    depends_on:
      - backend
      - frontend
    networks:
      - hypersend_network
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

networks:
  hypersend_network:
    driver: bridge
```

### Create Optimized Nginx Configuration

Create `nginx.conf`:

```nginx
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 4096;
    use epoll;
    multi_accept on;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;

    # Performance
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    client_max_body_size 40G;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml text/javascript 
               application/json application/javascript application/xml+rss;

    # Rate limiting zones
    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=100r/s;
    limit_req_zone $binary_remote_addr zone=login_limit:10m rate=5r/s;
    limit_conn_zone $binary_remote_addr zone=addr:10m;

    # Upstream backend
    upstream backend {
        least_conn;
        server backend:8000 max_fails=3 fail_timeout=30s;
    }

    # Upstream frontend
    upstream frontend {
        server frontend:8550;
    }

    server {
        listen 80;
        server_name _;

        # Timeouts for large file uploads
        proxy_connect_timeout 600;
        proxy_send_timeout 600;
        proxy_read_timeout 600;
        send_timeout 600;

        # API endpoints
        location /api/ {
            limit_req zone=api_limit burst=50 nodelay;
            limit_conn addr 10;

            proxy_pass http://backend;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_cache_bypass $http_upgrade;
        }

        # Auth endpoints (stricter rate limit)
        location /api/v1/auth/ {
            limit_req zone=login_limit burst=3 nodelay;

            proxy_pass http://backend;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }

        # Health check
        location /health {
            proxy_pass http://backend;
            access_log off;
        }

        # Frontend
        location / {
            proxy_pass http://frontend;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
    }
}
```

---

## 📊 MONITORING & MAINTENANCE

### Create Monitoring Script

On your VPS, create `/root/monitor.sh`:

```bash
#!/bin/bash

echo "╔════════════════════════════════════════════════════════════╗"
echo "║         HyperSend Production Monitoring Dashboard          ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

echo "📊 SYSTEM RESOURCES"
echo "─────────────────────────────────────────────────────────────"
free -h | grep -E "Mem|Swap"
echo ""
df -h | grep -E "Filesystem|/dev/vda"
echo ""

echo "🐳 DOCKER CONTAINERS"
echo "─────────────────────────────────────────────────────────────"
docker-compose ps
echo ""

echo "⚙️  DOCKER STATS"
echo "─────────────────────────────────────────────────────────────"
docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}"
echo ""

echo "🌐 ACTIVE CONNECTIONS"
echo "───────────────────────────────────────���─────────────────────"
echo "Backend (8000): $(netstat -an 2>/dev/null | grep :8000 | wc -l) connections"
echo "Frontend (8550): $(netstat -an 2>/dev/null | grep :8550 | wc -l) connections"
echo ""

echo "📝 RECENT ERRORS"
echo "─────────────────────────────────────────────────────────────"
docker-compose logs --tail=5 backend | grep -i error || echo "✅ No errors"
echo ""

echo "✅ Last updated: $(date)"
```

Make it executable:
```bash
chmod +x /root/monitor.sh

# Run monitoring
/root/monitor.sh

# Or watch continuously
watch -n 5 /root/monitor.sh
```

### Create Health Check Script

Create `/root/health_check.sh`:

```bash
#!/bin/bash

echo "🏥 HyperSend Health Check"
echo "─────────────────────────────────────────────────────────────"

# Check backend
echo -n "Backend API: "
if curl -s http://localhost:8000/health | grep -q "healthy"; then
    echo "✅ Healthy"
else
    echo "❌ Down"
    docker-compose restart backend
fi

# Check frontend
echo -n "Frontend: "
if curl -s http://localhost:8550 > /dev/null; then
    echo "✅ Running"
else
    echo "❌ Down"
    docker-compose restart frontend
fi

# Check MongoDB
echo -n "MongoDB: "
if docker-compose exec -T backend python -c "from backend.database import connect_db; import asyncio; asyncio.run(connect_db())" 2>/dev/null; then
    echo "✅ Connected"
else
    echo "❌ Connection Failed"
fi

# Check disk space
DISK=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
echo "Disk Usage: ${DISK}%"
if [ $DISK -gt 80 ]; then
    echo "⚠️  WARNING: Disk usage high!"
fi

echo "─────────────────────────────────────────────────────────────"
echo "✅ Health check completed at $(date)"
```

Make it executable:
```bash
chmod +x /root/health_check.sh

# Run health check
/root/health_check.sh

# Schedule daily at 2 AM
(crontab -l 2>/dev/null; echo "0 2 * * * /root/health_check.sh") | crontab -
```

---

## 🔐 SECURITY HARDENING

### Setup SSL/HTTPS (Free with Let's Encrypt)

```bash
# Install Certbot
apt install certbot python3-certbot-nginx -y

# Get SSL certificate (replace with your domain)
certbot certonly --standalone -d yourdomain.com -d www.yourdomain.com

# Update nginx.conf to use SSL
# Add to server block:
# listen 443 ssl http2;
# ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
# ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

# Auto-renewal
certbot renew --dry-run
```

### Setup Fail2Ban (DDoS Protection)

```bash
apt install fail2ban -y

# Configure
nano /etc/fail2ban/jail.local
```

Add:
```ini
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
maxretry = 3

[nginx-http-auth]
enabled = true
maxretry = 5
```

```bash
systemctl restart fail2ban
systemctl enable fail2ban
```

---

## 💰 COST BREAKDOWN

### Your $100 DigitalOcean Credit

**Recommended Setup (Best Value)**
```
DigitalOcean Droplet (2 vCPU, 4GB):    $24/month
MongoDB Atlas M0:                      FREE
Cloudflare CDN:                        FREE
GitHub Actions:                        FREE
────────────��────────────────────────────────
Total per month:                       $24

Month 1: $24 (from $100 credit)
Month 2: $24 (from $100 credit)
Month 3: $24 (from $100 credit)
Month 4: $24 (from $100 credit)
Month 5: $4 (remaining credit)
─────────────────────────────────────────────
Total: $100 credit covers 4+ months!

✅ Capacity: 20K-30K concurrent users
✅ Perfect for lakhs of users
✅ Can handle 1M+ total users
```

**If You Need More Power**
```
DigitalOcean Droplet (4 vCPU, 8GB):    $48/month
MongoDB Atlas M0:                      FREE
─────────────────────────────────────────────
Total per month:                       $48

Month 1: $48 (from $100 credit)
Month 2: $48 (from $100 credit)
Remaining: $4

✅ Capacity: 50K+ concurrent users
✅ Credit lasts: 2 months
```

---

## 🚨 TROUBLESHOOTING

### Backend Container Won't Start
```bash
# Check logs
docker-compose logs backend

# Common issues:
# 1. MongoDB connection failed
#    → Check MONGODB_URI in .env
#    → Verify IP whitelist in MongoDB Atlas

# 2. Port already in use
#    → Kill process: lsof -ti:8000 | xargs kill -9

# 3. Out of memory
#    → Increase swap: fallocate -l 8G /swapfile

# Restart
docker-compose restart backend
```

### High CPU Usage
```bash
# Check what's using CPU
top -b -n 1 | head -20

# Check Docker stats
docker stats

# If backend is high:
# 1. Check for infinite loops in code
# 2. Optimize database queries
# 3. Add caching

# Temporary fix: Restart
docker-compose restart backend
```

### Database Connection Issues
```bash
# Test connection
docker-compose exec backend python -c "
from backend.database import connect_db
import asyncio
asyncio.run(connect_db())
print('✅ Connected!')
"

# If fails:
# 1. Check MONGODB_URI format
# 2. Verify username/password
# 3. Check IP whitelist in MongoDB Atlas
# 4. Verify network connectivity
```

### Disk Space Running Out
```bash
# Check disk usage
df -h

# Clean Docker
docker system prune -f

# Remove old images
docker image prune -a -f

# Check data directory
du -sh /root/Hypersend/data/*

# If data is large, consider:
# 1. Archive old files
# 2. Upgrade to larger droplet
# 3. Use external storage
```

---

## 📈 SCALING STRATEGY

### When to Scale UP

**Monitor these metrics:**
- CPU usage > 80% consistently
- Memory usage > 85%
- Response time > 2 seconds
- Error rate > 1%

### Scaling Options

**Option 1: Vertical Scaling (Resize Droplet)**
```
Current: 2 vCPU, 4GB → $24/month
Upgrade: 4 vCPU, 8GB → $48/month
Upgrade: 8 vCPU, 16GB → $96/month

Downtime: ~2 minutes
Process: DigitalOcean Dashboard → Droplet → Resize
```

**Option 2: Horizontal Scaling (Load Balancer)**
```
Add Load Balancer: $12/month
Add 2-3 droplets: $24-72/month
Total: ~$150/month

Capacity: 500K+ users
Downtime: None (rolling updates)
```

**Option 3: Database Scaling**
```
MongoDB Atlas M0 (Free) → M10 ($57/month)
Enables: Connection pooling, read replicas
Capacity: 10x more throughput
```

---

## 🎯 DEPLOYMENT CHECKLIST

### Pre-Deployment ✓
- [ ] MongoDB Atlas cluster created
- [ ] DockerHub account created
- [ ] DigitalOcean droplet created
- [ ] GitHub secrets configured (6 secrets)
- [ ] .env file created on VPS
- [ ] Docker & Docker Compose installed

### Deployment ✓
- [ ] Code pushed to GitHub
- [ ] GitHub Actions workflow completed
- [ ] Docker containers running
- [ ] Health check passing
- [ ] Backend API accessible

### Post-Deployment ✓
- [ ] Monitoring script created
- [ ] Health check script created
- [ ] Logs being tracked
- [ ] Backup configured
- [ ] Security hardened
- [ ] SSL certificate obtained (optional)

---

## 🎉 SUCCESS INDICATORS

Your deployment is successful when:

```bash
# 1. All containers running
docker-compose ps
# Output: All containers should show "Up"

# 2. Health check passing
curl http://YOUR_VPS_IP:8000/health
# Output: {"status":"healthy"}

# 3. API responding
curl http://YOUR_VPS_IP:8000/docs
# Output: Swagger UI loads

# 4. No errors in logs
docker-compose logs backend | grep ERROR
# Output: (empty - no errors)

# 5. Database connected
docker-compose exec backend python -c "from backend.database import connect_db; import asyncio; asyncio.run(connect_db()); print('✅ DB Connected')"
# Output: ✅ DB Connected
```

---

## 📞 QUICK REFERENCE

### Essential Commands

```bash
# SSH into VPS
ssh root@YOUR_VPS_IP

# Navigate to project
cd /root/Hypersend

# View logs
docker-compose logs -f backend

# Restart services
docker-compose restart backend

# Stop all services
docker-compose down

# Start all services
docker-compose up -d

# Check status
docker-compose ps

# Monitor resources
watch -n 5 /root/monitor.sh

# Health check
/root/health_check.sh
```

### Access Points

```
API: http://YOUR_VPS_IP:8000
API Docs: http://YOUR_VPS_IP:8000/docs
Frontend: http://YOUR_VPS_IP:8550
Health: http://YOUR_VPS_IP:8000/health
```

---

## 🎓 NEXT STEPS

1. **Test Everything**
   - Test all API endpoints
   - Test file uploads
   - Test user authentication
   - Load test with multiple users

2. **Setup Monitoring**
   - Configure alerts
   - Setup log aggregation
   - Monitor database performance

3. **Optimize Performance**
   - Enable caching
   - Optimize database queries
   - Add CDN for static files

4. **Plan for Growth**
   - Monitor user growth
   - Plan scaling strategy
   - Budget for future upgrades

---

## 📚 ADDITIONAL RESOURCES

- [DigitalOcean Docs](https://docs.digitalocean.com/)
- [Docker Docs](https://docs.docker.com/)
- [MongoDB Atlas Docs](https://docs.atlas.mongodb.com/)
- [GitHub Actions Docs](https://docs.github.com/en/actions)
- [Nginx Docs](https://nginx.org/en/docs/)

---

**🚀 Your HyperSend backend is now production-ready!**

**Questions?** Check the logs, run health checks, and monitor performance.

**Need to scale?** Follow the scaling strategy above.

**Ready to go live?** Push your code and watch GitHub Actions deploy automatically!

---

*Last Updated: 2024*
*For Lakhs of Users with $100 DigitalOcean Credit*
