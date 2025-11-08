# 🚀 HyperSend Self-Hosting Roadmap

Complete step-by-step guide to self-host HyperSend on your own server.

---

## 📋 Table of Contents
1. [Prerequisites](#prerequisites)
2. [Local Development Setup](#local-development-setup)
3. [Production Server Setup](#production-server-setup)
4. [Deployment Options](#deployment-options)
5. [Post-Deployment](#post-deployment)
6. [Maintenance](#maintenance)

---

## 1️⃣ Prerequisites

### What You Need:
- [ ] **Server/VPS** (Minimum requirements)
  - 2 CPU cores
  - 4GB RAM
  - 40GB+ storage (for file uploads)
  - Ubuntu 20.04+ / Debian 11+ / Kali Linux
  
- [ ] **Domain Name** (Optional but recommended)
  - e.g., `hypersend.yourdomain.com`
  
- [ ] **Basic Knowledge**
  - Linux command line
  - Docker basics
  - SSH access

### Cost Estimates:
| Provider | Price/Month | Storage | Bandwidth |
|----------|-------------|---------|-----------|
| **Contabo** | $3-5 | 200GB | 32TB |
| **Hetzner** | $4-6 | 20GB | 20TB |
| **DigitalOcean** | $6-12 | 25GB | 1TB |
| **AWS Lightsail** | $5-10 | 20GB | 1TB |

---

## 2️⃣ Local Development Setup (Windows)

### Step 1: Setup MongoDB

**Option A: MongoDB Community (Recommended)**
```powershell
# Download MongoDB from: https://www.mongodb.com/try/download/community
# Install and start MongoDB service
net start MongoDB
```

**Option B: Docker MongoDB**
```powershell
docker run -d -p 27017:27017 --name mongodb mongo:latest
```

### Step 2: Configure Environment
```powershell
# Copy environment file
cp .env.example .env

# Edit .env file (use notepad or VS Code)
notepad .env
```

Update these values:
```env
MONGODB_URI=mongodb://localhost:27017/hypersend
SECRET_KEY=your-very-secure-random-secret-key-here
DEBUG=True
API_HOST=0.0.0.0
API_PORT=8000
DATA_ROOT=./data
```

### Step 3: Install Dependencies
```powershell
# Create virtual environment
python -m venv .venv

# Activate virtual environment
.\.venv\Scripts\activate

# Install backend dependencies
pip install -r backend/requirements.txt

# Install frontend dependencies
pip install -r frontend/requirements.txt
```

### Step 4: Run Locally
```powershell
# Terminal 1: Start Backend
python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

# Terminal 2: Start Frontend
python frontend/app.py
```

✅ **Test URLs:**
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs
- Frontend: http://localhost:8550

---

## 3️⃣ Production Server Setup

### Step 1: Get a VPS

**Recommended: Contabo ($3/month)**
1. Go to https://contabo.com
2. Choose VPS S SSD (€3.99/month)
3. Select Ubuntu 22.04 LTS
4. Complete purchase

**You'll receive:**
- IP Address: `123.45.67.89`
- SSH Username: `root`
- SSH Password: `your_password`

### Step 2: Connect to Server
```bash
# From your local machine
ssh root@123.45.67.89
```

### Step 3: Initial Server Setup
```bash
# Update system
apt update && apt upgrade -y

# Create non-root user
adduser hypersend
usermod -aG sudo hypersend

# Switch to new user
su - hypersend
```

### Step 4: Install Docker
```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add user to docker group
sudo usermod -aG docker $USER

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Logout and login again
exit
su - hypersend
```

### Step 5: Install MongoDB
```bash
# Import MongoDB GPG key
curl -fsSL https://www.mongodb.org/static/pgp/server-7.0.asc | \
   sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/mongodb-server-7.0.gpg

# Add MongoDB repository
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" | \
    sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list

# Install MongoDB
sudo apt update
sudo apt install -y mongodb-org

# Start MongoDB
sudo systemctl start mongod
sudo systemctl enable mongod
```

### Step 6: Clone Repository
```bash
# Clone your repository
git clone https://github.com/Mayankvlog/Hypersend.git
cd Hypersend

# Setup environment
cp .env.example .env
nano .env
```

Update .env for production:
```env
MONGODB_URI=mongodb://localhost:27017/hypersend
SECRET_KEY=CHANGE_THIS_TO_RANDOM_64_CHARACTER_STRING
DEBUG=False
API_HOST=0.0.0.0
API_PORT=8000
API_BASE_URL=http://YOUR_SERVER_IP:8000
DATA_ROOT=/data
```

### Step 7: Deploy with Docker
```bash
# Create data directories
mkdir -p data/tmp data/files
chmod 755 data

# Build and start containers
docker-compose up -d --build

# Check status
docker-compose ps
docker-compose logs -f
```

✅ **Your app is now running at:**
- Backend: http://YOUR_SERVER_IP:8000
- Frontend: http://YOUR_SERVER_IP:8550

---

## 4️⃣ Deployment Options

### Option A: Docker Compose (Recommended)

**Already done in Step 3!**

Manage with:
```bash
# Start
docker-compose up -d

# Stop
docker-compose down

# Restart
docker-compose restart

# View logs
docker-compose logs -f

# Update
git pull
docker-compose up -d --build
```

---

### Option B: Nginx Reverse Proxy + SSL

**Setup Nginx:**
```bash
# Install Nginx
sudo apt install -y nginx

# Create config
sudo nano /etc/nginx/sites-available/hypersend
```

Add this configuration:
```nginx
server {
    listen 80;
    server_name hypersend.yourdomain.com;

    client_max_body_size 0;
    proxy_request_buffering off;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Large file upload timeouts
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
```

**Enable site:**
```bash
sudo ln -s /etc/nginx/sites-available/hypersend /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

**Setup SSL (Free with Let's Encrypt):**
```bash
# Install Certbot
sudo apt install -y certbot python3-certbot-nginx

# Get SSL certificate
sudo certbot --nginx -d hypersend.yourdomain.com

# Auto-renewal (already setup by certbot)
sudo certbot renew --dry-run
```

✅ **Now accessible at:** https://hypersend.yourdomain.com

---

### Option C: Systemd Service (Auto-start on boot)

```bash
# Create service file
sudo nano /etc/systemd/system/hypersend.service
```

Add:
```ini
[Unit]
Description=HyperSend File Transfer Application
Requires=docker.service mongodb.service
After=docker.service mongodb.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/home/hypersend/Hypersend
ExecStart=/usr/local/bin/docker-compose up -d
ExecStop=/usr/local/bin/docker-compose down
User=hypersend

[Install]
WantedBy=multi-user.target
```

**Enable service:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable hypersend.service
sudo systemctl start hypersend.service

# Check status
sudo systemctl status hypersend
```

---

## 5️⃣ Post-Deployment

### Security Hardening

**1. Setup Firewall:**
```bash
# Install UFW
sudo apt install -y ufw

# Allow SSH, HTTP, HTTPS
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Enable firewall
sudo ufw enable
```

**2. Secure MongoDB:**
```bash
# Create MongoDB admin user
mongosh

use admin
db.createUser({
  user: "admin",
  pwd: "STRONG_PASSWORD_HERE",
  roles: [ { role: "userAdminAnyDatabase", db: "admin" } ]
})

use hypersend
db.createUser({
  user: "hypersend_user",
  pwd: "ANOTHER_STRONG_PASSWORD",
  roles: [ { role: "readWrite", db: "hypersend" } ]
})
exit

# Enable authentication
sudo nano /etc/mongod.conf
```

Add:
```yaml
security:
  authorization: enabled
```

Update .env:
```env
MONGODB_URI=mongodb://hypersend_user:ANOTHER_STRONG_PASSWORD@localhost:27017/hypersend?authSource=hypersend
```

**3. Setup Fail2Ban:**
```bash
sudo apt install -y fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

---

## 6️⃣ Maintenance

### Backup Strategy

**Daily Automated Backup:**
```bash
# Create backup script
nano ~/backup.sh
```

Add:
```bash
#!/bin/bash
BACKUP_DIR="/home/hypersend/backups"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p $BACKUP_DIR

# Backup MongoDB
mongodump --out=$BACKUP_DIR/mongodb_$DATE

# Backup uploaded files
tar -czf $BACKUP_DIR/files_$DATE.tar.gz /home/hypersend/Hypersend/data

# Delete backups older than 7 days
find $BACKUP_DIR -mtime +7 -delete

echo "Backup completed: $DATE"
```

```bash
chmod +x ~/backup.sh

# Add to crontab (daily at 2 AM)
crontab -e
# Add this line:
0 2 * * * /home/hypersend/backup.sh >> /home/hypersend/backup.log 2>&1
```

### Update Application

```bash
cd ~/Hypersend

# Backup first!
./backup.sh

# Pull latest changes
git pull origin main

# Rebuild and restart
docker-compose down
docker-compose up -d --build

# Check logs
docker-compose logs -f
```

### Monitor Resources

```bash
# Check disk space
df -h

# Check memory
free -h

# Check Docker containers
docker stats

# Check application logs
docker-compose logs -f backend
docker-compose logs -f frontend

# Check MongoDB logs
sudo tail -f /var/log/mongodb/mongod.log
```

### Clean Up Old Files

```bash
# Add to crontab (weekly cleanup)
crontab -e
# Add:
0 3 * * 0 find /home/hypersend/Hypersend/data/files -mtime +30 -delete
```

---

## 🎯 Quick Reference Commands

### Docker Commands
```bash
# Start services
docker-compose up -d

# Stop services
docker-compose down

# Restart services
docker-compose restart

# View logs
docker-compose logs -f

# Check status
docker-compose ps

# Rebuild
docker-compose up -d --build

# Remove all and rebuild
docker-compose down -v
docker-compose up -d --build
```

### MongoDB Commands
```bash
# Connect to MongoDB
mongosh

# Show databases
show dbs

# Use hypersend database
use hypersend

# Show collections
show collections

# Count users
db.users.countDocuments()

# Count files
db.files.countDocuments()
```

### System Commands
```bash
# Check service status
sudo systemctl status hypersend
sudo systemctl status mongodb
sudo systemctl status nginx

# View system logs
sudo journalctl -u hypersend -f

# Check disk usage
du -sh /home/hypersend/Hypersend/data/*

# Check open ports
sudo netstat -tulpn | grep LISTEN
```

---

## 🆘 Troubleshooting

### Backend Not Starting
```bash
# Check logs
docker-compose logs backend

# Common issues:
# 1. MongoDB not running
sudo systemctl status mongod
sudo systemctl start mongod

# 2. Port already in use
sudo lsof -i :8000

# 3. Permission issues
sudo chown -R hypersend:hypersend ~/Hypersend/data
```

### Cannot Upload Files
```bash
# Check permissions
ls -la data/
chmod 755 data/
chmod 755 data/tmp data/files

# Check disk space
df -h

# Check backend logs
docker-compose logs -f backend
```

### MongoDB Connection Failed
```bash
# Check MongoDB status
sudo systemctl status mongod

# Check connection
mongosh --eval "db.runCommand({ ping: 1 })"

# Check .env file
cat .env | grep MONGODB_URI
```

---

## 📊 Performance Optimization

### For Large Files (40GB uploads)

**1. Increase Nginx timeouts:**
```nginx
client_body_timeout 3600s;
send_timeout 3600s;
proxy_connect_timeout 3600s;
proxy_send_timeout 3600s;
proxy_read_timeout 3600s;
```

**2. Increase system limits:**
```bash
sudo nano /etc/security/limits.conf
```
Add:
```
* soft nofile 65535
* hard nofile 65535
```

**3. Optimize MongoDB:**
```bash
sudo nano /etc/mongod.conf
```
```yaml
storage:
  wiredTiger:
    engineConfig:
      cacheSizeGB: 2
```

---

## ✅ Success Checklist

- [ ] MongoDB installed and running
- [ ] Docker and Docker Compose installed
- [ ] Application running (docker-compose ps)
- [ ] Backend accessible (curl http://localhost:8000)
- [ ] Frontend accessible (curl http://localhost:8550)
- [ ] Nginx reverse proxy configured (if using domain)
- [ ] SSL certificate installed (if using domain)
- [ ] Firewall configured
- [ ] MongoDB authentication enabled
- [ ] Automated backups configured
- [ ] Systemd service enabled (auto-start on boot)
- [ ] Monitoring setup

---

## 🎉 You're Done!

Your HyperSend instance is now self-hosted and ready to use!

**Support:**
- GitHub Issues: https://github.com/Mayankvlog/Hypersend/issues
- Documentation: Check README.md

**Next Steps:**
1. Create your first user account
2. Test file upload (small file first)
3. Test large file upload (>1GB)
4. Setup monitoring (optional)
5. Configure backup strategy

---

**Made with ❤️ by the HyperSend Team**
