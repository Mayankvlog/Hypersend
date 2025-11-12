# HyperSend - Production Deployment Guide 🚀
## DigitalOcean + GitHub Actions + DockerHub + MongoDB Atlas

**Target**: Lakhs of users with $100 DigitalOcean credit

---

## 📋 Table of Contents
1. [Infrastructure Setup](#1-infrastructure-setup)
2. [MongoDB Atlas Setup](#2-mongodb-atlas-setup)
3. [DockerHub Setup](#3-dockerhub-setup)
4. [DigitalOcean VPS Setup](#4-digitalocean-vps-setup)
5. [GitHub Secrets Configuration](#5-github-secrets-configuration)
6. [Deploy Using GitHub Actions](#6-deploy-using-github-actions)
7. [Performance Optimization](#7-performance-optimization)
8. [Monitoring & Scaling](#8-monitoring--scaling)

---

## 1. Infrastructure Setup

### Recommended DigitalOcean Droplet (for lakhs of users)

**⭐ BEST FOR $100/2 MONTHS** (~$42/month)
```
Droplet: Regular (Not CPU-Optimized)
- 2 vCPUs
- 4 GB RAM  
- 80 GB SSD
- Cost: $24/month
- + MongoDB Atlas M0: FREE
- + Cloudflare: FREE
- Total: $24/month × 2 = $48 (saves $52!)
- Can handle: 20K-30K concurrent users
```

**Option B: More Users** (~$48/month)
```
Droplet: CPU-Optimized
- 4 vCPUs
- 8 GB RAM
- 100 GB SSD
- Cost: $48/month
- Can handle: ~50,000 concurrent users
- $100 credit = 2 months + $4 extra
```

**Option C: Maximum Performance** (~$96/month)
```
Droplet: CPU-Optimized
- 8 vCPUs
- 16 GB RAM
- 200 GB SSD
- Cost: $96/month
- Can handle: ~200,000 concurrent users
- $100 credit = 1 month + few days
```

### Additional Services (Free/Cheap)
- **MongoDB Atlas**: Free M0 (512MB) or M10 ($57/month for 2GB)
- **Cloudflare**: Free CDN + DDoS protection
- **GitHub Actions**: 2000 minutes/month free

---

## 2. MongoDB Atlas Setup

### Step 1: Create Free MongoDB Atlas Account
```
1. Go to: https://www.mongodb.com/cloud/atlas/register
2. Sign up with email
3. Create free M0 cluster (512MB)
   - For production: Upgrade to M10 ($57/month)
```

### Step 2: Configure Database
```bash
# In MongoDB Atlas Dashboard:
1. Click "Database" → "Browse Collections"
2. Create Database: "hypersend"
3. Create Collections:
   - users
   - chats
   - messages
   - files
   - uploads
   - refresh_tokens

# Set up indexes for performance
db.users.createIndex({ "email": 1 }, { unique: true })
db.messages.createIndex({ "chat_id": 1, "created_at": -1 })
db.chats.createIndex({ "participants": 1 })
```

### Step 3: Get Connection String
```
1. Click "Connect" → "Connect your application"
2. Copy connection string:
   mongodb+srv://username:password@cluster0.xxxxx.mongodb.net/hypersend

3. Save this for later (GitHub Secrets)
```

### Step 4: Network Access
```
1. Network Access → "Add IP Address"
2. Add: 0.0.0.0/0 (Allow from anywhere)
   - Or add your VPS IP for better security
```

---

## 3. DockerHub Setup

### Step 1: Create DockerHub Account
```
1. Go to: https://hub.docker.com/signup
2. Sign up (free account)
3. Username: Save this (e.g., "mayankvlog")
```

### Step 2: Create Access Token
```bash
1. Go to: Account Settings → Security → Access Tokens
2. Click "New Access Token"
3. Description: "hypersend-deployment"
4. Permissions: Read, Write, Delete
5. Copy token (you won't see it again!)
```

### Step 3: Create Repositories (Optional)
```
1. Create → "hypersend-backend"
2. Create → "hypersend-frontend"
```

---

## 4. DigitalOcean VPS Setup

### Step 1: Create Droplet

```bash
# On DigitalOcean Dashboard:
1. Click "Create" → "Droplets"
2. Choose:
   - Image: Ubuntu 22.04 LTS
   - Plan: CPU-Optimized ($48 or $96)
   - Region: Bangalore (BLR1) or nearest
   - Authentication: SSH key or Password
3. Hostname: hypersend-production
4. Click "Create Droplet"
5. Note the IP address
```

### Step 2: Initial Server Setup

```bash
# SSH into your server
ssh root@YOUR_VPS_IP

# Update system
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

# Create swap (for better performance)
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

# Create app directory
mkdir -p /root/Hypersend
cd /root/Hypersend
```

### Step 3: Setup Environment

```bash
# Clone your repository (you'll do this via GitHub Actions later)
# For now, create .env file

nano .env
```

Add this content:
```env
# MongoDB Atlas
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/hypersend

# Security (generate with: openssl rand -hex 32)
SECRET_KEY=your-super-secret-key-min-32-characters-long

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
API_BASE_URL=http://YOUR_VPS_IP:8000

# Production Settings
DEBUG=False
ENVIRONMENT=production

# Performance
CHUNK_SIZE=8388608
MAX_PARALLEL_CHUNKS=8
MAX_FILE_SIZE_BYTES=107374182400

# Rate Limiting (for lakhs of users)
RATE_LIMIT_PER_USER=500
RATE_LIMIT_WINDOW_SECONDS=60

# Storage
DATA_ROOT=/data
STORAGE_MODE=local
```

Save and exit (Ctrl+X, Y, Enter)

---

## 5. GitHub Secrets Configuration

### Add these secrets to your GitHub repository:

```
Go to: GitHub Repository → Settings → Secrets and variables → Actions → New repository secret
```

Add these 6 secrets:

```
1. DOCKERHUB_USERNAME
   Value: your-dockerhub-username

2. DOCKERHUB_TOKEN
   Value: your-dockerhub-access-token

3. VPS_HOST
   Value: YOUR_VPS_IP_ADDRESS

4. VPS_USER
   Value: root

5. VPS_PASSWORD
   Value: your-vps-password

6. MONGODB_URI
   Value: mongodb+srv://user:pass@cluster.mongodb.net/hypersend
```

---

## 6. Deploy Using GitHub Actions

### Step 1: Commit and Push

```powershell
# On your local machine
cd C:\Users\mayan\Downloads\Addidas\hypersend

# Make sure .env is in .gitignore (don't commit secrets)
git add .
git commit -m "Production deployment setup"
git push origin main
```

### Step 2: Auto-Deploy

GitHub Actions will automatically:
1. Build Docker images
2. Push to DockerHub
3. SSH into VPS
4. Pull latest images
5. Restart containers

### Step 3: Monitor Deployment

```
Go to: GitHub Repository → Actions tab
Watch the deployment progress
```

### Step 4: Verify Deployment

```bash
# SSH into VPS
ssh root@YOUR_VPS_IP

# Check containers
docker-compose ps

# Check logs
docker-compose logs -f backend

# Test health endpoint
curl http://YOUR_VPS_IP:8000/health
# Should return: {"status":"healthy"}
```

---

## 7. Performance Optimization

### Update docker-compose.yml for Production

Create `docker-compose.prod.yml`:

```yaml
version: '3.8'

services:
  backend:
    image: ${DOCKERHUB_USERNAME}/hypersend-backend:latest
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
    volumes:
      - ./data:/data
    networks:
      - hypersend_network
    deploy:
      resources:
        limits:
          cpus: '3'
          memory: 6G
        reservations:
          cpus: '2'
          memory: 4G
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  nginx:
    image: nginx:alpine
    container_name: hypersend_nginx
    restart: always
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - backend
    networks:
      - hypersend_network

networks:
  hypersend_network:
    driver: bridge
```

### Optimize Backend Config

Update `backend/config.py` for production:

```python
# Performance settings for lakhs of users
class Settings:
    # ... existing settings ...
    
    # Connection Pooling
    MONGODB_MAX_POOL_SIZE = 100
    MONGODB_MIN_POOL_SIZE = 10
    
    # Rate Limiting (more aggressive)
    RATE_LIMIT_PER_USER = 500
    RATE_LIMIT_WINDOW_SECONDS = 60
    
    # Chunk sizes (optimized for speed)
    CHUNK_SIZE = 8388608  # 8 MiB
    MAX_PARALLEL_CHUNKS = 8
    
    # Workers (for Uvicorn)
    WORKERS = 4  # For 4 vCPU droplet
```

### Update Nginx Configuration

Update `nginx.conf`:

```nginx
events {
    worker_connections 4096;
    use epoll;
}

http {
    # Performance
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css application/json application/javascript;
    
    # Rate limiting (global)
    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=100r/s;
    limit_req_zone $binary_remote_addr zone=login_limit:10m rate=5r/s;
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;
    limit_conn addr 10;
    
    upstream backend {
        least_conn;
        server backend:8000 max_fails=3 fail_timeout=30s;
    }
    
    server {
        listen 80;
        server_name _;
        
        client_max_body_size 40G;
        proxy_connect_timeout 600;
        proxy_send_timeout 600;
        proxy_read_timeout 600;
        send_timeout 600;
        
        # API endpoints
        location /api/ {
            limit_req zone=api_limit burst=50 nodelay;
            
            proxy_pass http://backend;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_set_header Host $host;
            proxy_cache_bypass $http_upgrade;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
        
        # Auth endpoints (stricter rate limit)
        location /api/v1/auth/ {
            limit_req zone=login_limit burst=3 nodelay;
            
            proxy_pass http://backend;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
        }
        
        # Health check
        location /health {
            proxy_pass http://backend;
            access_log off;
        }
    }
}
```

---

## 8. Monitoring & Scaling

### Setup Monitoring

```bash
# On VPS
# Install monitoring tools
apt install htop iotop nethogs -y

# Create monitoring script
nano /root/monitor.sh
```

Add:
```bash
#!/bin/bash
echo "=== System Resources ==="
free -h
df -h
echo ""
echo "=== Docker Stats ==="
docker stats --no-stream
echo ""
echo "=== Active Connections ==="
netstat -an | grep :8000 | wc -l
```

Make executable:
```bash
chmod +x /root/monitor.sh

# Run monitoring
watch -n 5 /root/monitor.sh
```

### Log Monitoring

```bash
# Backend logs
docker-compose logs -f --tail=100 backend

# Check for errors
docker-compose logs backend | grep ERROR

# Monitor access
docker-compose logs backend | grep "GET\|POST"
```

### Performance Metrics

```bash
# Create performance check script
nano /root/perf_check.sh
```

Add:
```bash
#!/bin/bash
echo "=== API Response Time ==="
time curl -s http://localhost:8000/health > /dev/null

echo "=== Database Connection ==="
docker-compose exec backend python -c "from backend.database import connect_db; import asyncio; asyncio.run(connect_db()); print('DB Connected')"

echo "=== Memory Usage ==="
docker stats --no-stream --format "table {{.Container}}\t{{.MemUsage}}\t{{.CPUPerc}}"
```

### Scaling Strategy

**When to scale UP:**
- CPU usage > 80% consistently
- Memory usage > 85%
- Response time > 2 seconds
- Error rate > 1%

**Scaling Options:**

1. **Vertical Scaling** (Resize Droplet)
```
- 4 vCPU → 8 vCPU ($48 → $96/month)
- Downtime: ~2 minutes
```

2. **Horizontal Scaling** (Load Balancer)
```
- Add Load Balancer ($12/month)
- Add 2-3 droplets
- Total cost: ~$150/month
- Can handle: 500K+ users
```

3. **Database Scaling**
```
- MongoDB Atlas M0 (Free) → M10 ($57/month)
- Connection pooling enabled
- Add read replicas
```

### Auto-Scaling (Advanced)

Create `auto_scale.sh`:
```bash
#!/bin/bash
# Check CPU usage
CPU=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)

if (( $(echo "$CPU > 80" | bc -l) )); then
    echo "High CPU! Consider scaling up"
    # Send alert
    curl -X POST https://api.telegram.org/bot<TOKEN>/sendMessage \
      -d chat_id=<CHAT_ID> \
      -d text="⚠️ HyperSend CPU usage at ${CPU}%"
fi
```

---

## 9. Security Hardening

### SSL/HTTPS Setup (Free with Let's Encrypt)

```bash
# Install Certbot
apt install certbot python3-certbot-nginx -y

# Get SSL certificate (replace with your domain)
certbot --nginx -d yourdomain.com -d www.yourdomain.com

# Auto-renewal
certbot renew --dry-run
```

### Firewall Rules

```bash
# Strict firewall
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp    # SSH
ufw allow 80/tcp    # HTTP
ufw allow 443/tcp   # HTTPS
ufw reload
```

### Fail2Ban (DDoS Protection)

```bash
apt install fail2ban -y

# Configure
nano /etc/fail2ban/jail.local
```

Add:
```ini
[sshd]
enabled = true
maxretry = 3

[nginx-http-auth]
enabled = true
```

```bash
systemctl restart fail2ban
```

---

## 10. Cost Breakdown

### ⭐ BEST PLAN: 2 Months with $100 Credit

**Budget Option (Recommended for 2 months)**
```
DigitalOcean Droplet (2 vCPU, 4GB):    $24/month
MongoDB Atlas M0:                      FREE
Cloudflare (CDN + DDoS):               FREE  
GitHub Actions:                        FREE
Domain (optional):                     $10/year

Month 1: $24 (from $100 credit)
Month 2: $24 (from $100 credit)
Total:   $48
Remaining credit: $52

✅ Capacity: 20K-30K concurrent users
✅ Credit lasts: Full 2 months + $52 extra
✅ Can upgrade anytime if traffic increases
```

**Mid-Tier Option (More users)**
```
DigitalOcean Droplet (4 vCPU, 8GB):    $48/month
MongoDB Atlas M0:                      FREE
Total per month:                       $48

Month 1: $48 (from $100 credit)
Month 2: $48 (from $100 credit)  
Total:   $96
Remaining credit: $4

✅ Capacity: 50K+ concurrent users
✅ Credit lasts: Full 2 months
```

**High Performance Option (Max users in Month 1)**
```
DigitalOcean Droplet (8 vCPU, 16GB):   $96/month
MongoDB Atlas M10:                     $57/month
Total per month:                       $153

Month 1: $100 (credit exhausted)
Month 2: Pay $153

✅ Capacity: 200K+ concurrent users
⚠️ Not recommended for 2-month budget
```

### Scaling Strategy for 2 Months

**Week 1-4: Start Small**
- Use $24/month droplet (2 vCPU, 4GB)
- Monitor traffic and performance
- Cost: $24

**Week 5-8: Scale if Needed**
- If traffic > 20K users: Upgrade to $48/month
- Cost: $24 + $48 = $72 total
- Remaining: $28 credit

**Smart Tip:** Start small, scale up only when needed!

---

## 11. Deployment Checklist

### Pre-Deployment
- [ ] MongoDB Atlas cluster created
- [ ] DockerHub account created
- [ ] DigitalOcean droplet created
- [ ] GitHub secrets configured
- [ ] Domain name configured (optional)
- [ ] SSL certificate obtained (optional)

### Deployment
- [ ] Code pushed to GitHub
- [ ] GitHub Actions workflow completed
- [ ] Docker containers running
- [ ] Health check passing
- [ ] Backend API accessible

### Post-Deployment
- [ ] Monitoring setup
- [ ] Logs being tracked
- [ ] Backup configured
- [ ] Performance tested
- [ ] Security hardened

---

## 12. Maintenance

### Daily Tasks
```bash
# Check system health
/root/monitor.sh

# Check logs
docker-compose logs --tail=50 backend
```

### Weekly Tasks
```bash
# Update system
apt update && apt upgrade -y

# Clean Docker
docker system prune -f

# Check disk space
df -h
```

### Monthly Tasks
```bash
# Review costs
# Check DigitalOcean billing

# Analyze performance
# Review MongoDB Atlas metrics

# Update dependencies
# Rebuild Docker images
```

---

## 13. Emergency Procedures

### Backend Down
```bash
# Quick restart
docker-compose restart backend

# Full restart
docker-compose down
docker-compose up -d

# Check logs
docker-compose logs backend
```

### Database Issues
```bash
# Check MongoDB connection
docker-compose exec backend python -c "from backend.database import connect_db; import asyncio; asyncio.run(connect_db())"

# Check MongoDB Atlas dashboard
# Verify network access
```

### High Load
```bash
# Temporary fix: Increase resources
docker-compose down
docker-compose up -d --scale backend=2

# Long-term: Resize droplet
```

---

## Support Commands

```bash
# Quick health check
curl http://YOUR_VPS_IP:8000/health

# API docs
http://YOUR_VPS_IP:8000/docs

# Container stats
docker stats

# System resources
htop

# Network connections
netstat -tulpn | grep LISTEN

# Disk usage
du -sh /root/Hypersend/*
```

---

## 🎉 Deployment Complete!

Your backend is now live and can handle lakhs of users!

**Access Points:**
- API: `http://YOUR_VPS_IP:8000`
- Docs: `http://YOUR_VPS_IP:8000/docs`
- Health: `http://YOUR_VPS_IP:8000/health`

**Next Steps:**
1. Test all endpoints
2. Setup monitoring alerts
3. Configure backups
4. Add your domain
5. Enable HTTPS

---

**Need Help?**
- Check logs: `docker-compose logs -f`
- Run debug: `python debug_and_fix.py`
- Monitor: `/root/monitor.sh`
