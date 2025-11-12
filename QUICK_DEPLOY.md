# HyperSend - Quick Deployment Guide 🚀

## 1. Local Testing (5 minutes)

```powershell
# Terminal 1 - Backend
uvicorn backend.main:app --reload

# Terminal 2 - Frontend  
flet run frontend/app.py
```

**Test URLs:**
- Backend API: http://localhost:8000
- Backend Docs: http://localhost:8000/docs
- Frontend: http://localhost:8550

---

## 2. Docker Local (10 minutes)

```powershell
# Build and start
docker-compose up --build

# Stop
docker-compose down

# View logs
docker-compose logs -f
```

---

## 3. Production Deploy (30 minutes)

### Step 1: Prepare VPS
```bash
# SSH into VPS
ssh root@YOUR_VPS_IP

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh

# Install Docker Compose
apt-get install docker-compose -y

# Create directory
mkdir -p ~/Hypersend
cd ~/Hypersend
```

### Step 2: Configure GitHub Secrets
Go to: `GitHub Repo → Settings → Secrets → Actions`

Add these secrets:
```
DOCKERHUB_USERNAME=your_username
DOCKERHUB_TOKEN=your_token
VPS_HOST=your_vps_ip
VPS_USER=root
VPS_PASSWORD=your_password
```

### Step 3: Deploy
```powershell
# Commit and push
git add .
git commit -m "Deploy to production"
git push origin main
```

✅ GitHub Actions will automatically:
1. Build Docker images
2. Push to DockerHub
3. Deploy to your VPS
4. Start the containers

### Step 4: Verify
```bash
# Check health
curl http://YOUR_VPS_IP:8000/health

# View containers
docker-compose ps

# View logs
docker-compose logs -f
```

---

## 4. Common Commands

### Development
```powershell
# Install dependencies
pip install -r backend/requirements.txt
pip install -r frontend/requirements.txt

# Run tests
python validate_backend.py
python debug_and_fix.py

# Format code
black backend/ frontend/
```

### Docker
```powershell
# Rebuild single service
docker-compose build backend
docker-compose build frontend

# Restart service
docker-compose restart backend

# Clean everything
docker-compose down -v
docker system prune -a

# Shell into container
docker-compose exec backend bash
docker-compose exec frontend bash
```

### Deployment
```bash
# On VPS - Manual update
cd ~/Hypersend
git pull origin main
docker-compose pull
docker-compose up -d

# View logs
docker-compose logs -f backend
docker-compose logs -f frontend

# Restart
docker-compose restart

# Stop
docker-compose down
```

---

## 5. Troubleshooting

### Backend won't start
```powershell
# Check logs
docker-compose logs backend

# Common fix
docker-compose down
docker-compose up --build
```

### Frontend can't connect
```powershell
# Check environment
docker-compose exec frontend env | grep API

# Fix: Update docker-compose.yml
# environment:
#   - API_BASE_URL=http://backend:8000
```

### MongoDB connection error
```powershell
# Check MongoDB is running
docker-compose ps

# Update .env with correct URI
# MONGODB_URI=mongodb://localhost:27017/hypersend
```

### Deployment fails
```bash
# On VPS, check Docker is running
systemctl status docker

# Check disk space
df -h

# Check logs
docker-compose logs
```

---

## 6. Environment Variables

**Required in `.env`:**
```env
MONGODB_URI=mongodb://localhost:27017/hypersend
SECRET_KEY=generate-with-openssl-rand-hex-32
API_BASE_URL=http://localhost:8000
```

**Required GitHub Secrets:**
```
DOCKERHUB_USERNAME
DOCKERHUB_TOKEN
VPS_HOST
VPS_USER
VPS_PASSWORD
```

---

## 7. Health Checks

```powershell
# Local
curl http://localhost:8000/health
curl http://localhost:8000/api/v1/auth/test

# Production
curl http://YOUR_VPS_IP:8000/health
curl http://YOUR_VPS_IP:8000/docs
```

---

## 8. Monitoring

```bash
# CPU/Memory usage
docker stats

# Logs (last 100 lines)
docker-compose logs --tail=100

# Follow logs
docker-compose logs -f

# Specific service
docker-compose logs -f backend
```

---

## Quick Debug

```powershell
# Run comprehensive debug
python debug_and_fix.py

# Check backend syntax
python validate_backend.py

# Test backend imports
python -c "from backend.main import app; print('✅ Backend OK')"

# Test frontend imports  
python -c "from frontend.app import main; print('✅ Frontend OK')"
```

---

## Port Reference

| Service  | Port | URL |
|----------|------|-----|
| Backend  | 8000 | http://localhost:8000 |
| Frontend | 8550 | http://localhost:8550 |
| MongoDB  | 27017 | mongodb://localhost:27017 |

---

## File Locations

```
Backend API: backend/main.py
Frontend App: frontend/app.py
Config: backend/config.py
Database: backend/database.py
Environment: .env
Docker: docker-compose.yml
CI/CD: .github/workflows/deploy-dockerhub.yml
```

---

**Need Help?**
1. Run: `python debug_and_fix.py`
2. Check: `FIXES_APPLIED.md`
3. Review: `debug_report.json`

---

✅ **Ready to Deploy!**
