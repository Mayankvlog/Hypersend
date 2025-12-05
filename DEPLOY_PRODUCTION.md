# 🚀 Production Deployment Guide - Hypersend/Zaply

## VPS Details
- **VPS IP**: 139.59.82.105
- **Service**: Docker Compose (nginx, backend, frontend, mongodb)

## Prerequisites
1. SSH access to VPS (root or sudo user)
2. Docker & Docker Compose installed on VPS
3. Git installed on VPS

## Deployment Steps

### Step 1: Connect to VPS
```bash
ssh root@139.59.82.105
```

### Step 2: Clone Repository
```bash
cd /root
git clone https://github.com/Mayankvlog/Hypersend.git
cd Hypersend
```

### Step 3: Create Production Environment File
```bash
cp .env.production.example .env.production
nano .env.production
```

**Required Settings in `.env.production`:**
```env
VPS_IP=139.59.82.105
MONGO_USER=hypersend
MONGO_PASSWORD=Mayank@#03
SECRET_KEY=your-secure-key-here
API_BASE_URL=http://139.59.82.105:8000
DEBUG=False
```

### Step 4: Create Docker Compose Override (Production)
```bash
cat > docker-compose.prod.yml << 'EOF'
version: '3.9'
services:
  nginx:
    restart: always
    ports:
      - "80:80"
      - "443:443"
  mongodb:
    restart: always
  backend:
    restart: always
  frontend:
    restart: always
EOF
```

### Step 5: Start Services
```bash
# Pull latest images
docker-compose pull

# Start all services in background
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Check status
docker-compose ps
```

### Step 6: Verify Deployment
```bash
# Check backend health
curl http://localhost:8000/health

# Check nginx health
curl http://localhost:8080/health

# Check MongoDB
docker-compose logs mongodb | tail -20

# Check backend logs
docker-compose logs backend | tail -20
```

## Troubleshooting

### Backend Not Starting
```bash
# Check logs
docker-compose logs backend --tail=50

# Restart backend
docker-compose restart backend

# Full rebuild
docker-compose up --build backend -d
```

### MongoDB Connection Issues
```bash
# Verify MongoDB is running
docker-compose ps mongodb

# Test connection
docker-compose exec backend python -c "
from backend.database import connect_db
import asyncio
asyncio.run(connect_db())
print('✅ MongoDB connected')
"
```

### Port Already in Use
```bash
# Find process on port 8000
lsof -i :8000

# Find process on port 8080
lsof -i :8080

# Kill process
kill -9 <PID>
```

## Monitoring

### View Logs
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f backend
docker-compose logs -f mongodb
docker-compose logs -f nginx
```

### Health Checks
```bash
# Backend health
curl http://139.59.82.105:8000/health

# API endpoint test
curl http://139.59.82.105:8000/api/auth/status

# Frontend health
curl http://139.59.82.105:8080/
```

## Auto-Restart on VPS Reboot

### Using systemd (Recommended)
```bash
sudo tee /etc/systemd/system/hypersend.service > /dev/null << EOF
[Unit]
Description=Hypersend Docker Compose Services
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
WorkingDirectory=/root/Hypersend
ExecStart=/usr/bin/docker-compose up -d
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable hypersend
sudo systemctl start hypersend
```

## Updating Code

```bash
cd /root/Hypersend

# Pull latest changes
git pull origin main

# Rebuild services
docker-compose build

# Restart services
docker-compose up -d

# Check status
docker-compose ps
```

## Security Checklist

- [ ] Change MONGO_PASSWORD in `.env.production`
- [ ] Generate new SECRET_KEY for backend
- [ ] Use HTTPS (configure SSL certificates)
- [ ] Set DEBUG=False in production
- [ ] Use strong database credentials
- [ ] Restrict MongoDB port to VPS only (don't expose 27017 externally)
- [ ] Enable firewall rules on VPS

## Support

For issues, check:
1. `docker-compose ps` - service status
2. `docker-compose logs <service>` - error logs
3. Backend health endpoint: `http://139.59.82.105:8000/health`
