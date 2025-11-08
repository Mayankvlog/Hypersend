# 🐳 DockerHub Deployment Setup Guide

Complete guide to deploy HyperSend using GitHub Actions + DockerHub + DigitalOcean VPS.

---

## 📋 Prerequisites

- [ ] GitHub account
- [ ] DockerHub account (free)
- [ ] DigitalOcean VPS
- [ ] SSH access to VPS

**Time:** 30 minutes  
**Cost:** Free (DockerHub) + VPS cost

---

## Part 1: DockerHub Setup

### Step 1: Create DockerHub Account

1. Go to: https://hub.docker.com/signup
2. Sign up (free account)
3. Verify email

### Step 2: Create Access Token

1. Login to DockerHub
2. Go to: https://hub.docker.com/settings/security
3. Click **"New Access Token"**
4. Name: `HyperSend GitHub Actions`
5. Permissions: **Read, Write, Delete**
6. Click **"Generate"**
7. **Copy token immediately** (won't be shown again)

**Token example:** `dckr_pat_xxxxxxxxxxxxxxxxxxxxx`

### Step 3: Create Repositories (Optional)

DockerHub will auto-create repositories on first push, but you can create manually:

1. Go to: https://hub.docker.com/repositories
2. Click **"Create Repository"**
3. Name: `hypersend-backend`
4. Visibility: **Public** (free) or Private (paid)
5. Create another: `hypersend-frontend`

---

## Part 2: GitHub Secrets Setup

### Step 1: Add DockerHub Secrets

Go to: https://github.com/Mayankvlog/Hypersend/settings/secrets/actions

Click **"New repository secret"** and add:

| Secret Name | Value | Example |
|-------------|-------|---------|
| `DOCKERHUB_USERNAME` | Your DockerHub username | `mayankvlog` |
| `DOCKERHUB_TOKEN` | Access token from Step 2 | `dckr_pat_xxxxx...` |
| `VPS_HOST` | Your VPS IP address | `143.198.123.45` |
| `VPS_USER` | SSH username | `hypersend` |
| `VPS_SSH_KEY` | Private SSH key | `-----BEGIN...` |

### Step 2: Get SSH Private Key

**On your Windows PC:**
```powershell
# View your private key
Get-Content $HOME\.ssh\id_ed25519

# Copy entire output including:
# -----BEGIN OPENSSH PRIVATE KEY-----
# ... key content ...
# -----END OPENSSH PRIVATE KEY-----
```

Paste this as `VPS_SSH_KEY` secret.

---

## Part 3: Update Project Files

### Files already created:
- ✅ `.github/workflows/deploy-dockerhub.yml`
- ✅ Updated `docker-compose.yml`

### Update docker-compose.yml (if needed)

Make sure it uses DockerHub images:

```yaml
version: '3.8'

services:
  backend:
    image: ${DOCKERHUB_USERNAME:-mayankvlog}/hypersend-backend:latest
    container_name: hypersend_backend
    ports:
      - "8000:8000"
    environment:
      - MONGODB_URI=${MONGODB_URI}
      - SECRET_KEY=${SECRET_KEY}
      - DATA_ROOT=/data
      - API_HOST=0.0.0.0
      - API_PORT=8000
    volumes:
      - ./data:/data
    restart: unless-stopped
    networks:
      - hypersend_network

  frontend:
    image: ${DOCKERHUB_USERNAME:-mayankvlog}/hypersend-frontend:latest
    container_name: hypersend_frontend
    ports:
      - "8550:8550"
    environment:
      - API_BASE_URL=http://backend:8000
    depends_on:
      - backend
    restart: unless-stopped
    networks:
      - hypersend_network

networks:
  hypersend_network:
    driver: bridge
```

---

## Part 4: VPS Setup

### Step 1: Setup Environment Variables on VPS

SSH into your VPS:
```bash
ssh hypersend@YOUR_VPS_IP
```

Create `.env` file:
```bash
cd ~/Hypersend
nano .env
```

Add:
```env
DOCKERHUB_USERNAME=your_dockerhub_username
MONGODB_URI=mongodb://hypersend_user:PASSWORD@localhost:27017/hypersend?authSource=hypersend
SECRET_KEY=your-secret-key-here
DATA_ROOT=/home/hypersend/Hypersend/data
API_HOST=0.0.0.0
API_PORT=8000
DEBUG=False
```

Save: `Ctrl+X`, `Y`, `Enter`

### Step 2: Update docker-compose.yml on VPS

Make sure VPS has the updated docker-compose.yml:
```bash
cd ~/Hypersend
git pull origin main
```

---

## Part 5: Test Deployment

### Step 1: Commit and Push

**On your local machine:**
```powershell
cd C:\Users\mayan\Downloads\Addidas\hypersend

# Stage changes
git add .github/workflows/deploy-dockerhub.yml
git add docker-compose.yml
git add DOCKERHUB_SETUP.md

# Commit
git commit -m "Add DockerHub deployment workflow"

# Push
git push origin main
```

### Step 2: Monitor GitHub Actions

1. Go to: https://github.com/Mayankvlog/Hypersend/actions
2. Watch the workflow run
3. Should complete in 5-10 minutes

**Workflow steps:**
1. ✅ Checkout code
2. ✅ Login to DockerHub
3. ✅ Build backend image
4. ✅ Push to DockerHub
5. ✅ Build frontend image
6. ✅ Push to DockerHub
7. ✅ SSH to VPS
8. ✅ Pull images
9. ✅ Restart containers
10. ✅ Health check

### Step 3: Verify Deployment

**Check on VPS:**
```bash
ssh hypersend@YOUR_VPS_IP

# Check running containers
docker-compose ps

# Check logs
docker-compose logs -f

# Check images
docker images | grep hypersend
```

**Test in browser:**
- Backend: `http://YOUR_VPS_IP:8000`
- API Docs: `http://YOUR_VPS_IP:8000/docs`
- Frontend: `http://YOUR_VPS_IP:8550`

---

## 🎯 Deployment Workflow

```
Local Change
    ↓
Git Push
    ↓
GitHub Actions Triggered
    ↓
Build Docker Images
    ↓
Push to DockerHub
    ↓
SSH to VPS
    ↓
Pull from DockerHub
    ↓
Restart Containers
    ↓
Live! 🎉
```

---

## 📊 Advantages of DockerHub

### vs GitHub Container Registry (GHCR):

| Feature | DockerHub | GHCR |
|---------|-----------|------|
| **Free Public Repos** | ✅ Unlimited | ✅ Unlimited |
| **Free Private Repos** | 1 | ✅ Unlimited |
| **Pull Rate Limit** | 200/6hr (free) | No limit |
| **Ease of Use** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Community** | Huge | Growing |
| **Integration** | Excellent | Good |

### Why DockerHub:
- ✅ Industry standard
- ✅ Easy to use
- ✅ Great documentation
- ✅ Public images discoverable
- ✅ Docker Hub UI for management

---

## 🔄 Manual Deployment (Without GitHub Actions)

If you want to deploy manually:

### Step 1: Build Images Locally

```powershell
# Backend
docker build -t mayankvlog/hypersend-backend:latest ./backend

# Frontend
docker build -t mayankvlog/hypersend-frontend:latest ./frontend
```

### Step 2: Push to DockerHub

```powershell
# Login
docker login -u mayankvlog

# Push
docker push mayankvlog/hypersend-backend:latest
docker push mayankvlog/hypersend-frontend:latest
```

### Step 3: Deploy on VPS

```bash
# SSH to VPS
ssh hypersend@YOUR_VPS_IP

# Pull and restart
cd ~/Hypersend
docker-compose pull
docker-compose up -d
```

---

## 🛠️ Useful Commands

### Local Development

```powershell
# Build images locally
docker-compose build

# Run locally
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

### On VPS

```bash
# Pull latest images
docker-compose pull

# Restart services
docker-compose restart

# View logs
docker-compose logs -f backend
docker-compose logs -f frontend

# Check container status
docker-compose ps

# SSH into container
docker exec -it hypersend_backend bash

# View resource usage
docker stats
```

### DockerHub

```bash
# Login
docker login

# List images
docker images

# Remove old images
docker image prune -a

# Tag image
docker tag hypersend-backend:latest mayankvlog/hypersend-backend:v1.0

# Push specific tag
docker push mayankvlog/hypersend-backend:v1.0
```

---

## 🔒 Security Best Practices

### 1. Use Access Tokens (Not Password)
✅ Already done in setup

### 2. Rotate Tokens Regularly
```bash
# Every 3-6 months:
# 1. Create new DockerHub token
# 2. Update GitHub secret
# 3. Delete old token
```

### 3. Use Environment Variables
```bash
# Never commit secrets
# Always use .env file (gitignored)
```

### 4. Limit Token Permissions
```bash
# Only give Read/Write
# Don't give Admin access
```

---

## 🐛 Troubleshooting

### Error: DockerHub Login Failed

```bash
# Check credentials
docker login -u mayankvlog

# Verify token in GitHub secrets
# Make sure DOCKERHUB_TOKEN is correct
```

### Error: Image Not Found

```bash
# Verify image name
docker images | grep hypersend

# Check DockerHub repository
# Visit: https://hub.docker.com/u/mayankvlog
```

### Error: SSH Connection Failed

```bash
# Test SSH manually
ssh hypersend@YOUR_VPS_IP

# Check firewall
sudo ufw status

# Verify SSH key
cat ~/.ssh/authorized_keys
```

### Error: Container Not Starting

```bash
# Check logs
docker-compose logs backend

# Check .env file
cat .env

# Verify MongoDB is running
sudo systemctl status mongod
```

---

## 📈 Monitoring

### Check Deployment Status

```bash
# On VPS
docker-compose ps

# Expected output:
# NAME                  STATUS    PORTS
# hypersend_backend     Up        0.0.0.0:8000->8000/tcp
# hypersend_frontend    Up        0.0.0.0:8550->8550/tcp
```

### View Real-time Logs

```bash
# All services
docker-compose logs -f

# Backend only
docker-compose logs -f backend

# Last 100 lines
docker-compose logs --tail=100
```

### Check DockerHub

1. Go to: https://hub.docker.com/u/mayankvlog
2. See your repositories
3. Check pull statistics
4. View tags

---

## 🎉 Success Checklist

- [ ] DockerHub account created
- [ ] Access token generated
- [ ] GitHub secrets configured
- [ ] Workflow file added
- [ ] docker-compose.yml updated
- [ ] .env file created on VPS
- [ ] First deployment successful
- [ ] Backend accessible
- [ ] Frontend accessible
- [ ] Logs looking good

---

## 💰 Cost Summary

| Service | Cost |
|---------|------|
| DockerHub (Public) | **$0/month** |
| GitHub Actions | **$0/month** (2000 min free) |
| DigitalOcean VPS | $6-24/month |
| **Total** | **$6-24/month** |

---

## 🚀 Next Steps

1. ✅ Setup complete
2. ✅ Test deployment working
3. Setup domain + SSL (optional)
4. Add monitoring (Grafana)
5. Configure backups
6. Setup CI/CD for frontend
7. Add automated tests

---

## 📚 Resources

- DockerHub Docs: https://docs.docker.com/docker-hub/
- GitHub Actions: https://docs.github.com/actions
- Docker Compose: https://docs.docker.com/compose/
- DigitalOcean: https://docs.digitalocean.com/

---

**Made with ❤️ for HyperSend Community**
