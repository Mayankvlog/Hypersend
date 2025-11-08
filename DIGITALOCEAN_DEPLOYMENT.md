# 🚀 HyperSend Production Deployment
## DigitalOcean + GitHub Actions + Docker

Complete step-by-step guide for professional production deployment.

---

## 📋 Prerequisites

- [ ] GitHub account
- [ ] DigitalOcean account
- [ ] Credit/Debit card (for VPS)
- [ ] Domain name (optional)
- [ ] SSH key (we'll create)

**Total Time:** 45-60 minutes  
**Cost:** $6-12/month

---

## 🎯 Part 1: DigitalOcean VPS Setup

### Step 1: Create DigitalOcean Account

1. Go to: https://www.digitalocean.com/
2. Sign up (new users get $200 credit for 60 days)
3. Verify email
4. Add payment method

### Step 2: Create SSH Key (On Your PC)

**Windows PowerShell:**
```powershell
# Generate SSH key
ssh-keygen -t ed25519 -C "your_email@example.com"

# Location: C:\Users\mayan\.ssh\id_ed25519
# Press Enter for default location
# Set passphrase (optional, can leave empty)

# Copy public key
Get-Content $HOME\.ssh\id_ed25519.pub | Set-Clipboard
```

**The public key is now copied to clipboard.**

### Step 3: Add SSH Key to DigitalOcean

1. Go to: https://cloud.digitalocean.com/account/security
2. Click **"Add SSH Key"**
3. Paste the public key (from clipboard)
4. Name: `my-laptop` or `hypersend-key`
5. Click **"Add SSH Key"**

### Step 4: Create Droplet (VPS)

1. Go to: https://cloud.digitalocean.com/droplets
2. Click **"Create Droplet"**

**Configuration:**
```yaml
Region: Choose closest to you
  - New York (USA)
  - London (Europe)
  - Bangalore (India)

Image: Ubuntu 22.04 LTS x64

Droplet Type: Basic

CPU Options: Regular
  - $6/month: 1GB RAM, 1 vCPU, 25GB SSD
  - $12/month: 2GB RAM, 1 vCPU, 50GB SSD (Recommended)

Authentication: SSH Key
  - Select your added SSH key

Hostname: hypersend-prod

Enable: Monitoring (free)

Click: Create Droplet
```

**Wait 1-2 minutes for droplet creation.**

### Step 5: Get Droplet IP Address

After creation:
- Note your **IP Address**: e.g., `143.198.123.45`
- Save this, you'll need it multiple times

---

## 🔧 Part 2: Server Initial Setup

### Step 1: Connect to VPS

**PowerShell:**
```powershell
# Connect via SSH
ssh root@143.198.123.45

# Type 'yes' when asked about fingerprint
# You should now be logged into your server
```

### Step 2: Update System

```bash
# Update package list
apt update

# Upgrade installed packages
apt upgrade -y

# Install essential tools
apt install -y curl wget git ufw
```

### Step 3: Create Non-Root User

```bash
# Create user
adduser hypersend

# Set password (choose strong password)
# Press Enter for other prompts (leave default)

# Add to sudo group
usermod -aG sudo hypersend

# Copy SSH key to new user
rsync --archive --chown=hypersend:hypersend ~/.ssh /home/hypersend
```

### Step 4: Setup Firewall

```bash
# Allow SSH
ufw allow OpenSSH

# Allow HTTP and HTTPS
ufw allow 80/tcp
ufw allow 443/tcp

# Allow backend port
ufw allow 8000/tcp

# Enable firewall
ufw --force enable

# Check status
ufw status
```

### Step 5: Switch to New User

```bash
# Exit root session
exit

# Reconnect as hypersend user
ssh hypersend@143.198.123.45
```

---

## 🐳 Part 3: Install Docker

```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add user to docker group
sudo usermod -aG docker $USER

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Logout and login again for group changes
exit
ssh hypersend@143.198.123.45

# Verify installations
docker --version
docker-compose --version
```

---

## 📦 Part 4: Install MongoDB

```bash
# Import MongoDB GPG key
curl -fsSL https://www.mongodb.org/static/pgp/server-7.0.asc | \
   sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/mongodb-server-7.0.gpg

# Add MongoDB repository
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" | \
    sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list

# Update and install
sudo apt update
sudo apt install -y mongodb-org

# Start MongoDB
sudo systemctl start mongod
sudo systemctl enable mongod

# Verify
sudo systemctl status mongod
```

---

## 🔐 Part 5: Secure MongoDB

```bash
# Connect to MongoDB
mongosh

# Create admin user
use admin
db.createUser({
  user: "admin",
  pwd: "CHANGE_THIS_STRONG_PASSWORD",
  roles: [ { role: "userAdminAnyDatabase", db: "admin" } ]
})

# Create hypersend database user
use hypersend
db.createUser({
  user: "hypersend_user",
  pwd: "CHANGE_THIS_STRONG_PASSWORD_TOO",
  roles: [ { role: "readWrite", db: "hypersend" } ]
})

# Exit
exit

# Enable authentication
sudo nano /etc/mongod.conf
```

Add these lines:
```yaml
security:
  authorization: enabled
```

Save: `Ctrl+X`, `Y`, `Enter`

```bash
# Restart MongoDB
sudo systemctl restart mongod
```

---

## 📁 Part 6: Deploy Application Manually (First Time)

```bash
# Clone repository
cd ~
git clone https://github.com/Mayankvlog/Hypersend.git
cd Hypersend

# Create .env file
cp .env.example .env
nano .env
```

**Update .env:**
```env
MONGODB_URI=mongodb://hypersend_user:YOUR_MONGODB_PASSWORD@localhost:27017/hypersend?authSource=hypersend
SECRET_KEY=GENERATE_RANDOM_64_CHAR_STRING_HERE
DEBUG=False
API_HOST=0.0.0.0
API_PORT=8000
API_BASE_URL=http://YOUR_DROPLET_IP:8000
DATA_ROOT=/home/hypersend/Hypersend/data
UPLOAD_EXPIRE_HOURS=24
```

Generate SECRET_KEY:
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

Save: `Ctrl+X`, `Y`, `Enter`

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

**Test:** Open browser → `http://YOUR_DROPLET_IP:8000`

If working, proceed to GitHub Actions automation.

---

## ⚙️ Part 7: GitHub Actions Setup

### Step 1: Create GitHub Secrets

1. Go to: https://github.com/Mayankvlog/Hypersend/settings/secrets/actions
2. Click **"New repository secret"**

**Add these secrets:**

| Name | Value | How to Get |
|------|-------|------------|
| `VPS_HOST` | `143.198.123.45` | Your droplet IP |
| `VPS_USER` | `hypersend` | Your server username |
| `VPS_SSH_KEY` | `-----BEGIN OPENSSH PRIVATE KEY-----...` | See below |
| `GHCR_TOKEN` | `ghp_xxxxxxxxxxxx` | GitHub PAT (see below) |

**Get SSH Private Key:**
```powershell
# On your Windows PC
Get-Content $HOME\.ssh\id_ed25519
# Copy entire output including BEGIN and END lines
```

**Get GitHub Token:**
1. Go to: https://github.com/settings/tokens
2. **Generate new token (classic)**
3. Name: `HyperSend Deployment`
4. Scopes: Select `write:packages` and `read:packages`
5. Generate and copy token

### Step 2: Create GitHub Actions Workflow

```bash
# On your VPS
cd ~/Hypersend
mkdir -p .github/workflows
nano .github/workflows/deploy.yml
```

**Add this content:**
```yaml
name: Deploy to DigitalOcean

on:
  push:
    branches: [ main ]
    paths:
      - 'backend/**'
      - 'frontend/**'
      - 'docker-compose.yml'
      - '.github/workflows/deploy.yml'

jobs:
  deploy:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Login to GitHub Container Registry
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GHCR_TOKEN }}

      - name: Build and push backend image
        uses: docker/build-push-action@v5
        with:
          context: ./backend
          push: true
          tags: ghcr.io/${{ github.repository_owner }}/hypersend-backend:latest
          cache-from: type=gha
          cache-to: type=gha,mode=max

      - name: Build and push frontend image
        uses: docker/build-push-action@v5
        with:
          context: ./frontend
          push: true
          tags: ghcr.io/${{ github.repository_owner }}/hypersend-frontend:latest
          cache-from: type=gha
          cache-to: type=gha,mode=max

      - name: Deploy to VPS
        uses: appleboy/ssh-action@v1.0.3
        with:
          host: ${{ secrets.VPS_HOST }}
          username: ${{ secrets.VPS_USER }}
          key: ${{ secrets.VPS_SSH_KEY }}
          script: |
            cd ~/Hypersend
            
            # Login to GHCR
            echo ${{ secrets.GHCR_TOKEN }} | docker login ghcr.io -u ${{ github.actor }} --password-stdin
            
            # Pull latest images
            docker-compose pull
            
            # Restart services
            docker-compose up -d --no-build
            
            # Clean up old images
            docker image prune -af
            
            # Show status
            docker-compose ps
```

Save: `Ctrl+X`, `Y`, `Enter`

### Step 3: Update docker-compose.yml

```bash
nano docker-compose.yml
```

**Update to use GHCR images:**
```yaml
version: '3.8'

services:
  backend:
    image: ghcr.io/mayankvlog/hypersend-backend:latest
    container_name: hypersend_backend
    ports:
      - "8000:8000"
    environment:
      - MONGODB_URI=${MONGODB_URI}
      - SECRET_KEY=${SECRET_KEY}
      - DATA_ROOT=/data
      - API_HOST=0.0.0.0
      - API_PORT=8000
      - DEBUG=False
    volumes:
      - ./data:/data
    restart: unless-stopped
    networks:
      - hypersend_network

  frontend:
    image: ghcr.io/mayankvlog/hypersend-frontend:latest
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

Save and commit:
```bash
git add .github/workflows/deploy.yml docker-compose.yml
git commit -m "Add GitHub Actions deployment workflow"
git push origin main
```

---

## 🎉 Part 8: Test Automated Deployment

### Make a change and push:
```bash
# Make any small change
echo "# Test deployment" >> README.md

git add .
git commit -m "Test automated deployment"
git push origin main
```

### Monitor deployment:
1. Go to: https://github.com/Mayankvlog/Hypersend/actions
2. Watch the deployment process
3. Should complete in 5-10 minutes

---

## 🌐 Part 9: Setup Domain (Optional)

### Step 1: Point Domain to VPS

In your domain registrar (Cloudflare/Namecheap/GoDaddy):

**Add DNS Records:**
```
Type: A
Name: @
Value: YOUR_DROPLET_IP
TTL: 3600

Type: A
Name: www
Value: YOUR_DROPLET_IP
TTL: 3600
```

### Step 2: Install Nginx

```bash
# Install Nginx
sudo apt install -y nginx

# Create config
sudo nano /etc/nginx/sites-available/hypersend
```

**Add configuration:**
```nginx
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;

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
        
        # Large file timeouts
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
```

```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/hypersend /etc/nginx/sites-enabled/

# Test config
sudo nginx -t

# Restart Nginx
sudo systemctl restart nginx
```

### Step 3: Setup SSL with Let's Encrypt

```bash
# Install Certbot
sudo apt install -y certbot python3-certbot-nginx

# Get SSL certificate
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com

# Enter email
# Agree to terms
# Choose option 2 (redirect HTTP to HTTPS)

# Test auto-renewal
sudo certbot renew --dry-run
```

**Your site is now accessible via HTTPS!**

---

## 📊 Part 10: Monitoring & Maintenance

### Check Application Status

```bash
# View running containers
docker-compose ps

# View logs
docker-compose logs -f

# View backend logs only
docker-compose logs -f backend

# Check disk space
df -h

# Check memory
free -h

# Check MongoDB status
sudo systemctl status mongod
```

### Backup Script

```bash
# Create backup script
nano ~/backup.sh
```

**Add:**
```bash
#!/bin/bash
BACKUP_DIR="/home/hypersend/backups"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Backup MongoDB
mongodump --uri="mongodb://hypersend_user:YOUR_PASSWORD@localhost:27017/hypersend?authSource=hypersend" --out=$BACKUP_DIR/mongodb_$DATE

# Backup files
tar -czf $BACKUP_DIR/files_$DATE.tar.gz /home/hypersend/Hypersend/data

# Delete old backups (keep last 7 days)
find $BACKUP_DIR -mtime +7 -delete

echo "Backup completed: $DATE"
```

```bash
# Make executable
chmod +x ~/backup.sh

# Add to crontab (daily at 2 AM)
crontab -e
```

Add line:
```
0 2 * * * /home/hypersend/backup.sh >> /home/hypersend/backup.log 2>&1
```

---

## 🎯 Complete Deployment Flow

```mermaid
graph LR
    A[Git Push] --> B[GitHub Actions]
    B --> C[Build Docker Images]
    C --> D[Push to GHCR]
    D --> E[SSH to VPS]
    E --> F[Pull Images]
    F --> G[Restart Containers]
    G --> H[Live!]
```

### Workflow:
1. Make code changes locally
2. Commit and push to GitHub
3. GitHub Actions automatically:
   - Builds Docker images
   - Pushes to GitHub Container Registry
   - SSHs into your VPS
   - Pulls latest images
   - Restarts containers
4. Your app is updated! 🎉

---

## ✅ Success Checklist

- [ ] DigitalOcean droplet created
- [ ] SSH access configured
- [ ] Docker installed
- [ ] MongoDB installed and secured
- [ ] Application deployed manually (first time)
- [ ] GitHub secrets configured
- [ ] GitHub Actions workflow created
- [ ] Automated deployment tested
- [ ] Domain configured (optional)
- [ ] SSL certificate installed (optional)
- [ ] Backup script configured
- [ ] Monitoring setup

---

## 🆘 Troubleshooting

### Cannot SSH to VPS
```bash
# Check if SSH service running
sudo systemctl status ssh

# Check firewall
sudo ufw status

# Try verbose SSH
ssh -v hypersend@YOUR_IP
```

### Docker containers not starting
```bash
# Check logs
docker-compose logs

# Check disk space
df -h

# Restart Docker
sudo systemctl restart docker
```

### GitHub Actions failing
- Check secrets are correctly added
- Verify SSH key has no passphrase
- Check VPS is accessible from internet
- View Actions logs for specific error

### MongoDB connection issues
```bash
# Check MongoDB status
sudo systemctl status mongod

# Test connection
mongosh "mongodb://hypersend_user:PASSWORD@localhost:27017/hypersend?authSource=hypersend"

# Check logs
sudo tail -f /var/log/mongodb/mongod.log
```

---

## 💰 Monthly Cost Breakdown

| Item | Cost |
|------|------|
| DigitalOcean Droplet (2GB) | $12/month |
| Domain name (optional) | $1/month ($12/year) |
| **Total** | **$12-13/month** |

**With $200 credit:** First 16 months free! 🎉

---

## 🎉 You're Done!

Your HyperSend is now:
- ✅ Running on production VPS
- ✅ Auto-deployed via GitHub Actions
- ✅ Secured with firewall
- ✅ MongoDB authenticated
- ✅ Backed up daily
- ✅ Monitored

**Access your app:**
- Backend API: `http://YOUR_IP:8000`
- Frontend: `http://YOUR_IP:8550`
- API Docs: `http://YOUR_IP:8000/docs`

**With domain:**
- `https://yourdomain.com`

---

**Made with ❤️ for HyperSend Community**
