# 🚀 HyperSend - Quick Deploy to DigitalOcean

**Complete deployment in 30-45 minutes**

---

## 📋 Pre-requisites

- [ ] DigitalOcean account (with $100 credit)
- [ ] Credit/Debit card
- [ ] GitHub account
- [ ] Windows PowerShell

---

## 🎯 Step 1: Create DigitalOcean Account

### Get $100 Free Credit:

1. **Go to**: https://www.digitalocean.com/
2. **Sign up** with email
3. **Verify email**
4. **Add payment method** (required, won't charge)
5. **Apply credit** (Check promotions section)

---

## 🔑 Step 2: Create SSH Key (5 minutes)

### On Your Windows PC:

```powershell
# Open PowerShell and run:
ssh-keygen -t ed25519 -C "your_email@example.com"

# Press Enter for default location:
# C:\Users\mayan\.ssh\id_ed25519

# Press Enter twice (no passphrase)

# Copy public key to clipboard:
Get-Content $HOME\.ssh\id_ed25519.pub | Set-Clipboard
```

### Add to DigitalOcean:

1. Go to: https://cloud.digitalocean.com/account/security
2. Click **"Add SSH Key"**
3. Paste key (Ctrl+V)
4. Name: `hypersend-key`
5. Click **"Add SSH Key"**

✅ **Done!**

---

## 💻 Step 3: Create 8GB Droplet (2 minutes)

### Via Web Interface:

1. Go to: https://cloud.digitalocean.com/droplets/new
2. **Choose Region**: Bangalore (closest to India)
3. **Choose Image**: Ubuntu 22.04 LTS x64
4. **Choose Size**: 
   - Click "Premium Intel"
   - Select **8GB RAM / 4 vCPUs** ($48/month)
5. **Authentication**: Select your SSH key
6. **Hostname**: `hypersend-prod`
7. **Enable**: Monitoring (free)
8. Click **"Create Droplet"**

⏳ Wait 1-2 minutes...

✅ **Note your IP address**: (e.g., 143.198.123.45)

---

## 🔧 Step 4: Initial Server Setup (10 minutes)

### Connect to Server:

```powershell
# Replace with your droplet IP:
ssh root@YOUR_DROPLET_IP

# Type 'yes' when asked
```

### Update System:

```bash
# Update packages
apt update && apt upgrade -y

# Install essentials
apt install -y curl wget git ufw
```

### Setup Firewall:

```bash
# Allow SSH, HTTP, HTTPS, and API
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 8000/tcp

# Enable firewall
ufw --force enable

# Check status
ufw status
```

✅ **Server ready!**

---

## 🐳 Step 5: Install Docker (5 minutes)

```bash
# Download and install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh

# Install Docker Compose
curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# Verify installation
docker --version
docker-compose --version
```

✅ **Docker installed!**

---

## 📦 Step 6: Deploy HyperSend (10 minutes)

### Clone Repository:

```bash
# Clone your project
cd ~
git clone https://github.com/Mayankvlog/Hypersend.git
cd Hypersend
```

### Setup Environment:

```bash
# Copy example env
cp .env.example .env

# Edit environment file
nano .env
```

### Update .env file:

```env
# MongoDB (we'll use MongoDB Atlas free tier)
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/hypersend

# Security (generate strong key)
SECRET_KEY=your-very-long-random-secret-key-min-64-characters-here
ALGORITHM=HS256

# API Settings
API_HOST=0.0.0.0
API_PORT=8000
API_BASE_URL=http://YOUR_DROPLET_IP:8000

# File Storage
DATA_ROOT=/home/root/Hypersend/data
MAX_FILE_SIZE_BYTES=42949672960

# Development
DEBUG=False
```

**Save**: `Ctrl+X`, then `Y`, then `Enter`

### Generate Secret Key:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
# Copy output and paste in .env as SECRET_KEY
```

### Create Data Directories:

```bash
mkdir -p data/tmp data/files
chmod -R 755 data
```

---

## 🗄️ Step 7: Setup MongoDB (FREE Tier)

### Option A: MongoDB Atlas (Recommended - FREE):

1. Go to: https://cloud.mongodb.com/
2. **Sign up** / Login
3. **Create FREE Cluster** (M0 - 512MB)
4. **Database Access**:
   - Create user: `hypersend_user`
   - Password: (strong password)
5. **Network Access**:
   - Add IP: `0.0.0.0/0` (allow all)
6. **Get Connection String**:
   - Click "Connect"
   - Choose "Connect your application"
   - Copy connection string
7. **Update .env**:
   ```bash
   nano .env
   # Update MONGODB_URI with your connection string
   ```

### Option B: Self-hosted MongoDB:

```bash
# Install MongoDB
curl -fsSL https://www.mongodb.org/static/pgp/server-7.0.asc | gpg --dearmor -o /etc/apt/trusted.gpg.d/mongodb-server-7.0.gpg

echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" | tee /etc/apt/sources.list.d/mongodb-org-7.0.list

apt update
apt install -y mongodb-org

# Start MongoDB
systemctl start mongod
systemctl enable mongod

# Update .env
MONGODB_URI=mongodb://localhost:27017/hypersend
```

---

## 🚀 Step 8: Start Application (2 minutes)

```bash
# Build and start containers
docker-compose up -d --build

# Check status
docker-compose ps

# View logs
docker-compose logs -f

# Wait for "Application startup complete"
# Press Ctrl+C to exit logs
```

### Test Backend:

```bash
# Open in browser:
http://YOUR_DROPLET_IP:8000/docs
```

✅ **Backend is live!**

---

## 🌐 Step 9: Setup Domain (Optional - 10 minutes)

### If you have a domain:

1. **Point domain to droplet IP**:
   - Add A record: `@` → `YOUR_DROPLET_IP`
   - Add A record: `www` → `YOUR_DROPLET_IP`

2. **Install Nginx**:
```bash
apt install -y nginx

# Create config
nano /etc/nginx/sites-available/hypersend
```

3. **Nginx Configuration**:
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
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600s;
    }
}
```

4. **Enable site**:
```bash
ln -s /etc/nginx/sites-available/hypersend /etc/nginx/sites-enabled/
nginx -t
systemctl restart nginx
```

5. **Install SSL (FREE)**:
```bash
apt install -y certbot python3-certbot-nginx
certbot --nginx -d yourdomain.com -d www.yourdomain.com
```

---

## 🎉 Step 10: Setup GitHub Auto-Deploy (Optional)

### Create GitHub Secrets:

1. Go to: https://github.com/Mayankvlog/Hypersend/settings/secrets/actions
2. Add these secrets:

| Name | Value |
|------|-------|
| `VPS_HOST` | Your droplet IP |
| `VPS_USER` | `root` |
| `VPS_SSH_KEY` | Your private SSH key |
| `GHCR_TOKEN` | GitHub Personal Access Token |

### Get SSH Private Key:

```powershell
# On your Windows PC:
Get-Content $HOME\.ssh\id_ed25519
# Copy entire output including BEGIN/END lines
```

### Create GitHub Token:

1. Go to: https://github.com/settings/tokens
2. Generate new token (classic)
3. Select: `write:packages`, `read:packages`
4. Copy token

Now every push to `main` branch will auto-deploy! 🚀

---

## ✅ Verification Checklist

- [ ] Droplet created (8GB, $48/month)
- [ ] SSH access working
- [ ] Docker installed
- [ ] MongoDB configured (Atlas or self-hosted)
- [ ] Application deployed
- [ ] Backend accessible: `http://IP:8000/docs`
- [ ] Firewall configured
- [ ] (Optional) Domain configured
- [ ] (Optional) SSL installed
- [ ] (Optional) GitHub Actions setup

---

## 🔍 Useful Commands

### Check Application Status:
```bash
docker-compose ps
docker-compose logs -f backend
```

### Restart Application:
```bash
docker-compose restart
```

### Update Application:
```bash
cd ~/Hypersend
git pull origin main
docker-compose down
docker-compose up -d --build
```

### Check Resources:
```bash
free -h          # RAM usage
df -h            # Disk usage
htop             # Real-time monitoring (install: apt install htop)
```

### View Logs:
```bash
docker-compose logs -f
docker-compose logs backend
```

---

## 📊 Monitor Usage

### DigitalOcean Dashboard:
- https://cloud.digitalocean.com/droplets
- Check: CPU, RAM, Bandwidth

### Install Monitoring (Optional):
```bash
# Netdata (real-time monitoring)
bash <(curl -Ss https://my-netdata.io/kickstart.sh)

# Access at: http://YOUR_IP:19999
```

---

## 🆘 Troubleshooting

### Can't connect via SSH:
```powershell
# Try verbose mode:
ssh -v root@YOUR_IP
```

### Docker containers not starting:
```bash
docker-compose logs
docker ps -a
```

### MongoDB connection error:
```bash
# Check MongoDB status:
systemctl status mongod

# View logs:
tail -f /var/log/mongodb/mongod.log
```

### Port already in use:
```bash
# Find process:
netstat -tulpn | grep 8000

# Kill process:
kill -9 <PID>
```

---

## 💰 Cost Tracking

```
8GB Droplet: $48/month
MongoDB Atlas: FREE (512MB)
Cloudflare CDN: FREE
SSL Certificate: FREE
Monitoring: FREE

Total: $48/month = $96 for 2 months
Your credit: $100
Remaining: $4
```

---

## 📱 Next Steps

1. **Test thoroughly** with real users
2. **Setup Cloudflare CDN** for better performance
3. **Add Redis caching** when traffic increases
4. **Monitor resources** via DO dashboard
5. **Scale horizontally** when needed

---

## 🎯 Support

- **Detailed Guide**: See `DIGITALOCEAN_DEPLOYMENT.md`
- **GitHub Issues**: https://github.com/Mayankvlog/Hypersend/issues
- **Fixes Guide**: See `FIXES_APPLIED.md`

---

**Ready to deploy?** Follow steps 1-8 carefully! 🚀

**Estimated Time**: 30-45 minutes
**Difficulty**: Medium
**Result**: Production-ready backend for 100K+ users!
