# 🚀 Hypersend - VPS Deployment Guide

**Deployment Target**: VPS IP `139.59.82.105`  
**Status**: ✅ Production Ready  
**Last Updated**: December 1, 2025

---

## 📋 Table of Contents

1. [Quick Start](#quick-start)
2. [VPS Setup](#vps-setup)
3. [Configuration](#configuration)
4. [Docker Deployment](#docker-deployment)
5. [Verification](#verification)
6. [Troubleshooting](#troubleshooting)
7. [Architecture](#architecture)

---

## ⚡ Quick Start

### Prerequisites
- VPS with Docker and Docker Compose installed
- SSH access to VPS (139.59.82.105)
- Git installed on VPS

### Deploy in 5 Minutes

```bash
# 1. SSH into VPS
ssh root@139.59.82.105

# 2. Clone repository
git clone https://github.com/Mayankvlog/Hypersend.git
cd Hypersend

# 3. Copy and configure environment
cp .env.example .env
nano .env  # Edit VPS settings if needed

# 4. Start all services
docker-compose up -d

# 5. Verify deployment
docker-compose ps
curl http://139.59.82.105:8000/health
```

✅ **Done!** Your Hypersend stack is running on VPS.

---

## 🔧 VPS Setup

### Step 1: Install Docker

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Docker Compose
sudo apt install docker-compose -y

# Verify installation
docker --version
docker-compose --version
```

### Step 2: Configure Firewall

```bash
# Enable UFW firewall
sudo ufw enable

# Allow SSH, HTTP, HTTPS
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Allow Hypersend ports
sudo ufw allow 8000/tcp  # Backend API
sudo ufw allow 8550/tcp  # Frontend
sudo ufw allow 27017/tcp # MongoDB (internal only)

# Verify rules
sudo ufw status
```

### Step 3: Clone Repository

```bash
# Navigate to deployment directory
mkdir -p /opt/hypersend
cd /opt/hypersend

# Clone repository
git clone https://github.com/Mayankvlog/Hypersend.git .

# Verify structure
ls -la
# Should show: docker-compose.yml, .env, backend/, frontend/, etc.
```

---

## ⚙️ Configuration

### Step 1: Update Environment Variables

```bash
# Edit .env file
nano .env
```

**Key settings for VPS deployment:**

```dotenv
# VPS Configuration
VPS_IP=139.59.82.105
DEBUG=False

# MongoDB
MONGO_USER=hypersend
MONGO_PASSWORD=Mayank@#03  # ⚠️ CHANGE THIS FOR PRODUCTION

# Security
SECRET_KEY=your-generated-secret-key  # ⚠️ GENERATE NEW KEY

# API
API_BASE_URL=http://139.59.82.105:8000
```

### Step 2: Generate Secure Keys (IMPORTANT!)

```bash
# Generate SECRET_KEY
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(32))"

# Example output:
# SECRET_KEY=4e9c2b4f9f7a4d0bbf2c8e7d3a1b6c9d4e2f7a9c3b8e1d0f2a4c6e8b0d2f4a

# Copy the output and update .env
```

### Step 3: Verify Configuration

```bash
# Check all environment variables
grep -E "VPS_IP|MONGO_PASSWORD|SECRET_KEY|DEBUG" .env

# Should output:
# VPS_IP=139.59.82.105
# MONGO_PASSWORD=Mayank@#03
# SECRET_KEY=your-secure-key
# DEBUG=False
```

---

## 🐳 Docker Deployment

### Start Services

```bash
# Build and start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Check service status
docker-compose ps
```

**Expected Output:**
```
NAME                 STATUS              PORTS
hypersend_mongodb    Up 20 seconds (healthy)   0.0.0.0:27017->27017/tcp
hypersend_backend    Up 15 seconds (healthy)   0.0.0.0:8000->8000/tcp
hypersend_frontend   Up 10 seconds (healthy)   0.0.0.0:8550->8550/tcp
```

### Monitoring Services

```bash
# View real-time logs
docker-compose logs -f backend

# Check specific service
docker-compose logs mongodb | tail -50

# CPU and memory usage
docker stats

# Restart a service
docker-compose restart backend
```

### Stop/Cleanup

```bash
# Stop services (data persists in volumes)
docker-compose stop

# Stop and remove containers
docker-compose down

# Remove data (WARNING: deletes database!)
docker-compose down -v
```

---

## ✅ Verification

### Test Backend Health

```bash
# Check if backend is responding
curl http://139.59.82.105:8000/health

# Expected response:
# {"status":"ok","message":"Hypersend API is running"}
```

### Test API Documentation

Open in browser:
```
http://139.59.82.105:8000/docs
```

### Test Frontend

Open in browser:
```
http://139.59.82.105:8550
```

### Test Database Connection

```bash
# Connect to MongoDB container
docker-compose exec mongodb mongosh -u hypersend -p Mayank@#03 --authenticationDatabase admin

# Inside mongosh:
> use hypersend
> db.users.find()
> exit
```

### Test Complete Flow

```bash
# 1. Register new user
curl -X POST http://139.59.82.105:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "name": "Test User",
    "password": "SecurePassword123"
  }'

# 2. Login
curl -X POST http://139.59.82.105:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePassword123"
  }'

# 3. Get user profile (use token from login response)
curl -X GET http://139.59.82.105:8000/api/v1/users/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

---

## 🔍 Troubleshooting

### MongoDB Won't Start

```bash
# Check MongoDB logs
docker-compose logs mongodb

# Common issue: Port already in use
sudo lsof -i :27017

# Fix: Kill process or use different port
sudo kill -9 <PID>

# Restart
docker-compose restart mongodb
```

### Backend Cannot Connect to MongoDB

```bash
# Check MongoDB is healthy
docker-compose ps

# Check backend logs
docker-compose logs backend | grep -i error

# Verify MongoDB authentication
docker-compose exec mongodb mongosh -u hypersend -p Mayank@#03 --authenticationDatabase admin

# If auth fails:
# 1. Stop MongoDB
# 2. Delete volume: docker volume rm hypersend_mongodb_data
# 3. Restart: docker-compose up -d
```

### Frontend Cannot Connect to Backend

```bash
# Check backend is responding
curl http://139.59.82.105:8000/health

# Check .env has correct VPS_IP
grep PRODUCTION_API_URL .env

# Restart frontend
docker-compose restart frontend

# Check frontend logs
docker-compose logs frontend | grep -i error
```

### Port Already in Use

```bash
# Check what's using port 8000
sudo lsof -i :8000

# Kill process
sudo kill -9 <PID>

# Or use different port (edit .env and docker-compose.yml)
```

### Out of Disk Space

```bash
# Check disk usage
df -h

# Clean up old Docker images
docker image prune -a

# Clean up unused volumes
docker volume prune

# Check data directory size
du -sh ./data
```

---

## 📊 Architecture

### Service Communication

```
┌─────────────────────────────────────┐
│      VPS 139.59.82.105              │
├─────────────────────────────────────┤
│                                     │
│  ┌─────────────┐  Internal Docker   │
│  │  Frontend   │◄──────Network──────┤
│  │  :8550      │  (172.20.0.0/16)   │
│  └──────┬──────┘                    │
│         │                           │
│         │ http://backend:8000       │
│         ▼                           │
│  ┌─────────────┐                    │
│  │  Backend    │                    │
│  │  :8000      │                    │
│  └──────┬──────┘                    │
│         │                           │
│         │ mongodb://               │
│         │ hypersend:pass@          │
│         │ mongodb:27017            │
│         ▼                           │
│  ┌─────────────┐                    │
│  │  MongoDB    │                    │
│  │  :27017     │                    │
│  └─────────────┘                    │
│                                     │
└─────────────────────────────────────┘

External Access:
  Frontend: http://139.59.82.105:8550
  Backend:  http://139.59.82.105:8000
  Docs:     http://139.59.82.105:8000/docs
  Health:   http://139.59.82.105:8000/health
```

### Data Flow

```
User's Device
    │
    │ HTTP Request
    │ (Login, Send Message, Upload File)
    ▼
Frontend (Flet UI) :8550
    │ JSON over HTTP
    ▼
Backend (FastAPI) :8000
    │ Async I/O
    ├─► Health Check
    ├─► Auth (JWT tokens)
    ├─► Chat Operations
    ├─► File Uploads
    └─► User Management
        │ Database queries
        ▼
    MongoDB :27017 (hypersend database)
        │ Collections:
        ├─ users
        ├─ chats
        ├─ messages
        ├─ files
        ├─ uploads
        ├─ refresh_tokens
        └─ reset_tokens
```

### Docker Services

| Service | Image | Port | Purpose |
|---------|-------|------|---------|
| **MongoDB** | mongo:7.0 | 27017 | NoSQL Database with auth |
| **Backend** | hypersend-backend:latest | 8000 | FastAPI REST APIs |
| **Frontend** | hypersend-frontend:latest | 8550 | Flet Web UI |

### Network Configuration

```
Network: hypersend_network
Driver: bridge
Subnet: 172.20.0.0/16

Service IPs (internal):
  mongodb:  172.20.0.2
  backend:  172.20.0.3
  frontend: 172.20.0.4
```

---

## 📈 Production Checklist

- [x] VPS has Docker and Docker Compose
- [x] Firewall configured for ports 8000, 8550
- [x] Repository cloned to VPS
- [x] `.env` file configured with VPS IP (139.59.82.105)
- [x] SECRET_KEY changed from default
- [x] MONGO_PASSWORD secured
- [x] DEBUG set to False
- [x] Docker services started: `docker-compose up -d`
- [x] All services healthy: `docker-compose ps`
- [x] Backend responding: `curl http://139.59.82.105:8000/health`
- [x] Frontend accessible: `http://139.59.82.105:8550`
- [x] Database authenticated: `mongosh -u hypersend -p <password>`

---

## 📞 Support

**Issues?** Check the README.md or run:

```bash
# View all logs
docker-compose logs

# Restart everything
docker-compose restart

# Full reset (careful!)
docker-compose down -v && docker-compose up -d
```

---

## 🔐 Security Tips

1. **Change Default Passwords**
   ```bash
   MONGO_PASSWORD=YourStrongPassword123!
   ```

2. **Generate Secure SECRET_KEY**
   ```bash
   python3 -c "import secrets; print(secrets.token_urlsafe(32))"
   ```

3. **Use HTTPS in Production**
   - Install SSL certificate with Let's Encrypt
   - Configure Nginx reverse proxy
   - See nginx.conf for configuration

4. **Backup Database Regularly**
   ```bash
   docker-compose exec mongodb mongodump --out /data/backup
   ```

5. **Monitor Logs**
   ```bash
   docker-compose logs -f backend | grep ERROR
   ```

---

**Deployment Complete! 🎉**  
Your Hypersend stack is now running on VPS 139.59.82.105

