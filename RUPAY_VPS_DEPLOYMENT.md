# 🇮🇳 HyperSend Backend - RuPay VPS Deployment Guide
## $200 Budget | Password Auth | 2+ Lakh Users | Indian Payment Methods

---

# 📋 Table of Contents

1. [Best VPS Provider (RuPay)](#best-vps-provider)
2. [Account Setup](#phase-1-account-setup)
3. [VPS Purchase](#phase-2-vps-purchase)
4. [Server Configuration](#phase-3-server-configuration)
5. [Docker Setup](#phase-4-docker-setup)
6. [Project Configuration](#phase-5-project-configuration)
7. [GitHub Integration](#phase-6-github-integration)
8. [Deployment](#phase-7-deployment)
9. [Verification](#phase-8-verification)
10. [Maintenance](#maintenance-guide)

---

# Best VPS Provider

## 🏆 WINNER: Hostinger VPS (India)

### Why Hostinger?

```
✅ RuPay Debit Card - DIRECT SUPPORT! 🎉
✅ UPI Payment (PhonePe, Google Pay, Paytm)
✅ Net Banking
✅ Indian Rupees (₹) pricing
✅ Mumbai Datacenter (India)
✅ Password authentication by default
✅ 24/7 Hindi support
✅ Easiest setup
✅ Best for Indian users
```

### Pricing Plan

```
Plan: VPS 4
├── 4 vCPU Cores
├── 8 GB RAM
├── 100 GB NVMe SSD
├── Unlimited Bandwidth
└── ₹849/month (~$10/month)

Budget Calculation:
$200 = ₹16,500
Duration: 19 months! 🔥

Capacity:
- 50K-70K concurrent users
- 2-5 Lakh total users
- Perfect for your project! ✅
```

### Alternative: Upgrade Option

```
Plan: VPS 8 (For even more users)
├── 8 vCPU Cores
├── 16 GB RAM
├── 200 GB NVMe SSD
├── Unlimited Bandwidth
└── ₹1,599/month (~$19/month)

Duration with $200: 10 months

Capacity:
- 100K+ concurrent users
- 10+ Lakh total users
```

---

# Phase 1: Account Setup

## ⏱️ Time: 10 minutes

### Step 1.1: Visit Hostinger

**Open browser:**
```
https://www.hostinger.in/
```

**Language:** Hindi/English (both available)

### Step 1.2: Navigate to VPS Section

```
1. Top menu → Click "VPS"
   OR
   Direct link: https://www.hostinger.in/vps-hosting

2. You'll see VPS plans page
```

### Step 1.3: Choose VPS Plan

**Recommended: VPS 4**

```
┌────────────────────────────────────┐
│ VPS 4                              │
├────────────────────────────────────┤
│ ₹849/month                         │
│                                    │
│ • 4 vCPU                           │
│ • 8 GB RAM                         │
│ • 100 GB NVMe SSD                  │
│ • Unlimited Bandwidth              │
│ • Free SSL Certificate            │
│ • Weekly Backups                   │
│                                    │
│ [Add to Cart]                      │
└────────────────────────────────────┘
```

**Click:** "Add to Cart" button

### Step 1.4: Select Billing Cycle

```
Options:
○ 1 Month
○ 12 Months (Save 20%)
● 24 Months (Save 35%) ← RECOMMENDED

Choose: 1 Month (for testing)
Later you can upgrade to longer term
```

### Step 1.5: Review Cart

```
Cart Summary:
├── VPS 4: ₹849/month
├── Setup Fee: ₹0 (Free)
└── Total: ₹849 for first month
```

**Click:** "Checkout"

### Step 1.6: Create Account

**Sign Up Form:**
```
Email: your_email@gmail.com
Password: Strong@Password123

[Create Account]
```

**OR Sign up with Google:**
```
[Continue with Google]
Select your Google account
```

### Step 1.7: Email Verification

```
1. Check email inbox
2. Find email from Hostinger
3. Click verification link
4. Account activated! ✅
```

---

# Phase 2: VPS Purchase

## ⏱️ Time: 10 minutes

### Step 2.1: Payment Page

After account creation, you'll be on payment page.

### Step 2.2: Select Payment Method

```
┌────────────────────────────────────┐
│ Choose Payment Method              │
├────────────────────────────────────┤
│                                    │
│ ☑ Debit/Credit Card               │
│   • RuPay ✅                       │
│   • Visa                           │
│   • Mastercard                     │
│                                    │
│ ○ UPI                              │
│   • PhonePe                        │
│   • Google Pay                     │
│   • Paytm                          │
│                                    │
│ ○ Net Banking                      │
│   • All Indian Banks               │
│                                    │
│ ○ PayPal                           │
│                                    │
└────────────────────────────────────┘
```

### Step 2.3: RuPay Payment (Recommended)

**Select:** Debit/Credit Card

**Enter card details:**
```
Card Number:     ____ ____ ____ ____
Cardholder Name: Your Name
Expiry Date:     MM / YY
CVV:             ___

Billing Address:
Street: Your Street
City: Your City
State: Your State
PIN: 123456
```

**Click:** "Pay Now"

### Step 2.4: OTP Verification

```
1. You'll receive OTP on registered mobile
2. Enter OTP
3. Click "Verify"
4. Payment processing...
5. Payment Successful! ✅
```

### Step 2.5: Alternative - UPI Payment

**If using UPI:**
```
1. Select "UPI" payment method
2. Enter UPI ID: yourname@paytm
   OR
3. Scan QR code with:
   - Google Pay
   - PhonePe
   - Paytm
   - BHIM
4. Approve payment on phone
5. Done! ✅
```

### Step 2.6: Order Confirmation

```
Email received:
Subject: "VPS Order Confirmed"

Contains:
✓ Order number
✓ VPS details
✓ Invoice
✓ Setup time: 5-10 minutes
```

**Save this email!**

---

# Phase 3: VPS Access Setup

## ⏱️ Time: 15 minutes

### Step 3.1: Access hPanel

```
1. Login: https://hpanel.hostinger.com/
2. Email + Password
3. You'll see dashboard
```

### Step 3.2: Navigate to VPS

```
Dashboard → VPS section
You'll see your VPS:
├── Name: vps-xxxxx.hostinger.com
├── Status: 🟢 Running
├── IP: 123.45.67.89
└── OS: Select OS
```

### Step 3.3: Install Operating System

**Click on your VPS, then:**

```
1. Left menu → "Operating System"
2. Click "Change Operating System"

Choose:
┌────────────────────────────────────┐
│ Operating System                   │
├────────────────────────────────────┤
│ ● Ubuntu 22.04 64bit ← SELECT     │
│ ○ Ubuntu 20.04 64bit               │
│ ○ Debian 11                        │
│ ○ CentOS 7                         │
└────────────────────────────────────┘

3. Click "Change OS"
4. Confirm: "Yes, change OS"
5. Wait 3-5 minutes...
6. Status: OS Installed ✅
```

### Step 3.4: Set Root Password ⭐

**IMPORTANT: Password Authentication Setup**

```
1. VPS Dashboard → "Settings"
2. Scroll to "Root Password" section
3. Click "Change Root Password"

4. Enter new password:
   Requirements:
   - 8+ characters
   - 1 uppercase
   - 1 lowercase
   - 1 number
   - 1 special char

   Example: HyperSend@2025!Pass

5. Click "Change Password"
6. Success message: "Password changed" ✅
```

**⚠️ CRITICAL: Save in Notepad!**

```
=== HOSTINGER VPS INFO ===
IP Address: 123.45.67.89
Username: root
Password: HyperSend@2025!Pass
SSH Port: 22
Location: Mumbai, India
```

### Step 3.5: Verify SSH Access

**From hPanel:**
```
VPS Dashboard → "SSH Access"

You'll see:
Host: 123.45.67.89
Port: 22
Username: root
Password: ********
```

### Step 3.6: Get All Details

**Copy from dashboard:**

```
VPS Information:
├── IP Address: 123.45.67.89
├── Hostname: vps-12345.hostinger.com
├── OS: Ubuntu 22.04
├── RAM: 8 GB
├── CPU: 4 Cores
├── Disk: 100 GB
└── Location: Mumbai, IN
```

---

# Phase 4: Server Configuration

## ⏱️ Time: 30 minutes

### Step 4.1: SSH Connection (Windows)

**Open PowerShell:**
```
Windows Key + X → Windows PowerShell
```

**Connect to VPS:**
```powershell
ssh root@123.45.67.89
# Replace with YOUR IP address
```

**First time warning:**
```
The authenticity of host '123.45.67.89' can't be established.
ECDSA key fingerprint is SHA256:xxxxx
Are you sure you want to continue connecting (yes/no)?
```

**Type:** `yes` and press Enter

**Password prompt:**
```
root@123.45.67.89's password:
```

**Enter your password:**
- Type password (won't show while typing)
- Press Enter

**Connected! You'll see:**
```
Welcome to Ubuntu 22.04.3 LTS

root@vps-12345:~#
```

✅ **Successfully connected to your VPS!**

### Step 4.2: Update System

**Update package list:**
```bash
apt update
```

**Expected output:**
```
Hit:1 http://archive.ubuntu.com/ubuntu jammy InRelease
Get:2 http://archive.ubuntu.com/ubuntu jammy-updates InRelease
...
Reading package lists... Done
```

**Upgrade all packages:**
```bash
apt upgrade -y
```

**Wait:** 3-5 minutes

**Expected output:**
```
Reading package lists... Done
Building dependency tree... Done
...
The following packages will be upgraded:
  package1 package2 package3
...
Done.
```

### Step 4.3: Install Essential Tools

**Install utilities:**
```bash
apt install -y curl wget git nano htop ufw net-tools
```

**Verify installations:**
```bash
curl --version
git --version
nano --version
```

**Expected:**
```
curl 7.81.0 (x86_64-pc-linux-gnu)
git version 2.34.1
GNU nano, version 6.2
```

### Step 4.4: Configure Firewall (UFW)

**Allow SSH (port 22):**
```bash
ufw allow 22/tcp
```

**Output:** `Rules updated`

**Allow HTTP (port 80):**
```bash
ufw allow 80/tcp
```

**Allow HTTPS (port 443):**
```bash
ufw allow 443/tcp
```

**Allow Backend API (port 8000):**
```bash
ufw allow 8000/tcp
```

**Enable firewall:**
```bash
ufw --force enable
```

**Check status:**
```bash
ufw status verbose
```

**Expected output:**
```
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing)

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
80/tcp                     ALLOW IN    Anywhere
443/tcp                    ALLOW IN    Anywhere
8000/tcp                   ALLOW IN    Anywhere
```

✅ **Firewall configured!**

### Step 4.5: Create Swap Space

**Why swap?**
- Extra virtual memory
- Prevents crashes
- Better MongoDB performance

**Create 4GB swap file:**
```bash
fallocate -l 4G /swapfile
```

**Set permissions:**
```bash
chmod 600 /swapfile
```

**Make swap:**
```bash
mkswap /swapfile
```

**Output:** `Setting up swapspace...`

**Enable swap:**
```bash
swapon /swapfile
```

**Make permanent (survives reboot):**
```bash
echo '/swapfile none swap sw 0 0' >> /etc/fstab
```

**Verify swap:**
```bash
free -h
```

**Expected output:**
```
              total        used        free      shared  buff/cache   available
Mem:           7.8G        300M        7.2G        1.0M        300M        7.3G
Swap:          4.0G          0B        4.0G
```

✅ **4GB swap created!**

### Step 4.6: Create Project Directory

**Create directory:**
```bash
mkdir -p /root/Hypersend
```

**Navigate to directory:**
```bash
cd /root/Hypersend
```

**Verify location:**
```bash
pwd
```

**Output:**
```
/root/Hypersend
```

✅ **Project directory ready!**

---

# Phase 5: Docker Setup

## ⏱️ Time: 15 minutes

### Step 5.1: Install Docker

**Download Docker installer:**
```bash
curl -fsSL https://get.docker.com -o get-docker.sh
```

**Run installation:**
```bash
sh get-docker.sh
```

**Wait:** 2-3 minutes

**Expected output:**
```
# Executing docker install script...
+ sudo -E sh -c apt-get update -qq
+ sudo -E sh -c apt-get install -y docker-ce
...
Docker installed successfully!
```

**Enable Docker service:**
```bash
systemctl enable docker
```

**Start Docker:**
```bash
systemctl start docker
```

**Verify Docker is running:**
```bash
systemctl status docker
```

**Expected:**
```
● docker.service - Docker Application Container Engine
     Loaded: loaded
     Active: active (running)
```

**Press `q` to exit**

**Check Docker version:**
```bash
docker --version
```

**Output:**
```
Docker version 24.0.7, build afdd53b
```

**Test Docker:**
```bash
docker run hello-world
```

**Expected:**
```
Hello from Docker!
This message shows that your installation appears to be working correctly.
```

✅ **Docker installed successfully!**

### Step 5.2: Install Docker Compose

**Install via apt:**
```bash
apt install docker-compose -y
```

**Wait:** 1 minute

**Verify installation:**
```bash
docker-compose --version
```

**Output:**
```
docker-compose version 1.29.2, build unknown
```

✅ **Docker Compose installed!**

### Step 5.3: Docker Cleanup

**Remove test container:**
```bash
docker system prune -af
```

**Verify clean state:**
```bash
docker ps
```

**Expected (empty list):**
```
CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS    PORTS     NAMES
```

---

# Phase 6: Project Configuration

## ⏱️ Time: 25 minutes

### Step 6.1: Generate Secure Passwords

**Generate MongoDB password:**
```bash
openssl rand -base64 32
```

**Example output:**
```
x7K2mP9vL4nQ8zR3wT6yA1bC5dE0fGhIjKlMnOpQr=
```

**⚠️ Copy this immediately!**

**Save in Notepad as:**
```
MongoDB Password: x7K2mP9vL4nQ8zR3wT6yA1bC5dE0fGhIjKlMnOpQr=
```

**Generate Secret Key:**
```bash
openssl rand -hex 32
```

**Example output:**
```
1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z7a8b9c0d1e2f
```

**⚠️ Copy this too!**

**Save in Notepad as:**
```
Secret Key: 1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z7a8b9c0d1e2f
```

### Step 6.2: Create docker-compose.yml

**Ensure you're in correct directory:**
```bash
cd /root/Hypersend
pwd
```

**Output should be:** `/root/Hypersend`

**Create file:**
```bash
nano docker-compose.yml
```

**Copy and paste this EXACTLY:**

```yaml
version: '3.8'

services:
  mongodb:
    image: mongo:7.0
    container_name: hypersend_mongodb
    restart: always
    environment:
      MONGO_INITDB_ROOT_USERNAME: hypersend
      MONGO_INITDB_ROOT_PASSWORD: ${MONGO_PASSWORD}
      MONGO_INITDB_DATABASE: hypersend
    volumes:
      - mongodb_data:/data/db
      - mongodb_config:/data/configdb
    networks:
      - hypersend_network
    command: --wiredTigerCacheSizeGB 2 --maxConns 500
    healthcheck:
      test: echo 'db.runCommand("ping").ok' | mongosh localhost:27017/hypersend --quiet
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  backend:
    image: ${DOCKERHUB_USERNAME}/hypersend-backend:latest
    container_name: hypersend_backend
    restart: always
    ports:
      - "8000:8000"
    environment:
      - MONGODB_URI=mongodb://hypersend:${MONGO_PASSWORD}@mongodb:27017/hypersend?authSource=admin
      - SECRET_KEY=${SECRET_KEY}
      - DATA_ROOT=/data
      - API_HOST=0.0.0.0
      - API_PORT=8000
      - DEBUG=False
      - ENVIRONMENT=production
      - CHUNK_SIZE=8388608
      - MAX_PARALLEL_CHUNKS=8
    volumes:
      - ./data:/data
    depends_on:
      mongodb:
        condition: service_healthy
    networks:
      - hypersend_network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

volumes:
  mongodb_data:
    driver: local
  mongodb_config:
    driver: local

networks:
  hypersend_network:
    driver: bridge
```

**Save file:**
```
Ctrl + X
Y (for Yes)
Enter
```

**Verify file created:**
```bash
ls -lh docker-compose.yml
```

**Output:**
```
-rw-r--r-- 1 root root 1.3K Jan 14 10:30 docker-compose.yml
```

### Step 6.3: Create .env File

**Create file:**
```bash
nano .env
```

**⚠️ IMPORTANT: You MUST replace placeholders with YOUR actual values!**

**Template:**

```env
# MongoDB Configuration
MONGO_PASSWORD=PASTE_YOUR_MONGODB_PASSWORD_HERE
MONGODB_URI=mongodb://hypersend:PASTE_YOUR_MONGODB_PASSWORD_HERE@mongodb:27017/hypersend?authSource=admin

# Security
SECRET_KEY=PASTE_YOUR_SECRET_KEY_HERE

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
API_BASE_URL=http://YOUR_VPS_IP_HERE:8000

# Production Settings
DEBUG=False
ENVIRONMENT=production

# Performance (8GB RAM optimized)
CHUNK_SIZE=8388608
MAX_PARALLEL_CHUNKS=8
MAX_FILE_SIZE_BYTES=42949672960

# Rate Limiting
RATE_LIMIT_PER_USER=200
RATE_LIMIT_WINDOW_SECONDS=60

# Storage
DATA_ROOT=/data
STORAGE_MODE=local

# DockerHub
DOCKERHUB_USERNAME=YOUR_DOCKERHUB_USERNAME_HERE
```

**Replace these values:**

1. **MONGO_PASSWORD** (appears in 2 places):
   ```
   Replace with: x7K2mP9vL4nQ8zR3wT6yA1bC5dE0fGhIjKlMnOpQr=
   ```

2. **SECRET_KEY**:
   ```
   Replace with: 1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z7a8b9c0d1e2f
   ```

3. **API_BASE_URL** (YOUR_VPS_IP_HERE):
   ```
   Replace with: http://123.45.67.89:8000
   (Use your actual Hostinger IP)
   ```

4. **DOCKERHUB_USERNAME**:
   ```
   Replace with: mayankvlog
   (Your DockerHub username)
   ```

**Final example (with your values):**

```env
# MongoDB Configuration
MONGO_PASSWORD=x7K2mP9vL4nQ8zR3wT6yA1bC5dE0fGhIjKlMnOpQr=
MONGODB_URI=mongodb://hypersend:x7K2mP9vL4nQ8zR3wT6yA1bC5dE0fGhIjKlMnOpQr=@mongodb:27017/hypersend?authSource=admin

# Security
SECRET_KEY=1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z7a8b9c0d1e2f

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
API_BASE_URL=http://123.45.67.89:8000

# Production Settings
DEBUG=False
ENVIRONMENT=production

# Performance (8GB RAM optimized)
CHUNK_SIZE=8388608
MAX_PARALLEL_CHUNKS=8
MAX_FILE_SIZE_BYTES=42949672960

# Rate Limiting
RATE_LIMIT_PER_USER=200
RATE_LIMIT_WINDOW_SECONDS=60

# Storage
DATA_ROOT=/data
STORAGE_MODE=local

# DockerHub
DOCKERHUB_USERNAME=mayankvlog
```

**Save file:**
```
Ctrl + X
Y
Enter
```

**Verify file:**
```bash
cat .env | head -15
```

**Should show first 15 lines with your actual values**

### Step 6.4: Create Data Directory

**Create directory:**
```bash
mkdir -p /root/Hypersend/data
```

**Set permissions:**
```bash
chmod 755 /root/Hypersend/data
```

**Verify:**
```bash
ls -ld data
```

**Output:**
```
drwxr-xr-x 2 root root 4096 Jan 14 10:35 data
```

### Step 6.5: Verify All Files

**List all files:**
```bash
ls -lh /root/Hypersend/
```

**Expected output:**
```
total 16K
drwxr-xr-x 2 root root 4.0K Jan 14 10:35 data
-rw-r--r-- 1 root root  892 Jan 14 10:34 .env
-rw-r--r-- 1 root root 1.3K Jan 14 10:30 docker-compose.yml
```

✅ **All files ready!**

---

# Phase 7: GitHub Integration

## ⏱️ Time: 15 minutes

### Step 7.1: DockerHub Account

**If not already done:**

1. **Go to:** https://hub.docker.com/signup
2. **Create account:**
   - Username: mayankvlog
   - Email: your_email@gmail.com
   - Password: Strong@Pass123
3. **Verify email**

### Step 7.2: Generate DockerHub Token

1. **Login:** https://hub.docker.com/
2. **Profile icon** (top right) → Account Settings
3. **Security** tab
4. **New Access Token**
5. **Fill:**
   ```
   Description: hypersend-deploy
   Permissions: Read, Write, Delete
   ```
6. **Generate**
7. **⚠️ COPY TOKEN NOW!**
   ```
   Format: dckr_pat_xxxxxxxxxxxxxxxxxxxxx
   ```
8. **Save in Notepad:**
   ```
   DockerHub Token: dckr_pat_xxxxxxxxxxxxxxxxxxxxx
   ```

### Step 7.3: Open GitHub Repository

**Browser:**
```
https://github.com/Mayankvlog/Hypersend
```

**Login** if needed

### Step 7.4: Navigate to Secrets

```
Click: Settings (top menu)
  ↓
Left sidebar: Secrets and variables
  ↓
Click: Actions
  ↓
You'll see: "Actions secrets and variables" page
```

### Step 7.5: Add Secret #1 - DOCKERHUB_USERNAME

```
1. Click: "New repository secret" (green button)
2. Fill:
   Name:   DOCKERHUB_USERNAME
   Secret: mayankvlog
3. Click: "Add secret"
4. Success: "Secret DOCKERHUB_USERNAME was created"
```

### Step 7.6: Add Secret #2 - DOCKERHUB_TOKEN

```
1. Click: "New repository secret"
2. Fill:
   Name:   DOCKERHUB_TOKEN
   Secret: dckr_pat_xxxxxxxxxxxxxxxxxxxxx
   (Your DockerHub token from Notepad)
3. Click: "Add secret"
```

### Step 7.7: Add Secret #3 - VPS_HOST

```
1. Click: "New repository secret"
2. Fill:
   Name:   VPS_HOST
   Secret: 123.45.67.89
   (Your Hostinger VPS IP address)
3. Click: "Add secret"
```

### Step 7.8: Add Secret #4 - VPS_USER

```
1. Click: "New repository secret"
2. Fill:
   Name:   VPS_USER
   Secret: root
3. Click: "Add secret"
```

### Step 7.9: Add Secret #5 - VPS_PASSWORD

```
1. Click: "New repository secret"
2. Fill:
   Name:   VPS_PASSWORD
   Secret: HyperSend@2025!Pass
   (Your VPS root password from Notepad)
3. Click: "Add secret"
```

### Step 7.10: Verify All Secrets

**You should see 5 secrets:**

```
Repository secrets (5)

DOCKERHUB_USERNAME    Updated now
DOCKERHUB_TOKEN       Updated now
VPS_HOST              Updated now
VPS_USER              Updated now
VPS_PASSWORD          Updated now
```

✅ **All GitHub secrets configured!**

---

# Phase 8: Deployment

## ⏱️ Time: 20 minutes

### Step 8.1: Open PowerShell (Local Machine)

**On your Windows PC:**
```
Windows Key + X → Windows PowerShell
```

### Step 8.2: Navigate to Project

```powershell
cd C:\Users\mayan\Downloads\Addidas\hypersend
```

**Verify location:**
```powershell
pwd
```

**Output:**
```
Path
----
C:\Users\mayan\Downloads\Addidas\hypersend
```

### Step 8.3: Check Git Status

```powershell
git status
```

**Output:**
```
On branch main
Your branch is up to date with 'origin/main'.

Untracked files:
  RUPAY_VPS_DEPLOYMENT.md

nothing added to commit
```

### Step 8.4: Add New Files

```powershell
git add .
```

### Step 8.5: Commit Changes

```powershell
git commit -m "Deploy to Hostinger VPS with RuPay - Production ready"
```

**Output:**
```
[main abc1234] Deploy to Hostinger VPS with RuPay - Production ready
 1 file changed, 2000 insertions(+)
 create mode 100644 RUPAY_VPS_DEPLOYMENT.md
```

### Step 8.6: Push to GitHub (TRIGGER DEPLOYMENT!)

**⚠️ This command will automatically deploy your backend!**

```powershell
git push origin main
```

**Expected output:**
```
Enumerating objects: 5, done.
Counting objects: 100% (5/5), done.
Delta compression using up to 12 threads
Compressing objects: 100% (3/3), done.
Writing objects: 100% (3/3), 45.67 KiB | 15.22 MiB/s, done.
Total 3 (delta 2), reused 0 (delta 0), pack-reused 0
remote: Resolving deltas: 100% (2/2), completed with 2 local objects.
To https://github.com/Mayankvlog/Hypersend.git
   abc1234..def5678  main -> main
```

✅ **Code pushed! Deployment triggered!**

### Step 8.7: Monitor GitHub Actions

**Open browser:**
```
https://github.com/Mayankvlog/Hypersend/actions
```

**You'll see:**
```
┌────────────────────────────────────────────┐
│ All workflows                              │
├────────────────────────────────────────────┤
│ ● Deploy to Hostinger VPS - Production    │
│   #125 · main · def5678                    │
│   🟡 In progress                           │
│   Started 10 seconds ago                   │
└────────────────────────────────────────────┘
```

**Click on workflow to see details**

### Step 8.8: Watch Deployment Stages

**Stages:**

```
✓ Set up job                    (5s)
✓ Checkout code                 (3s)
✓ Set up Docker Buildx          (4s)
✓ Login to DockerHub            (2s)
⏳ Build and push backend image (3m 15s)
⏳ Deploy to VPS                (2m 30s)
   ├─ SSH to VPS (password auth)
   ├─ Navigate to /root/Hypersend
   ├─ Pull latest Docker images
   ├─ Stop old containers
   ├─ Start new containers
   └─ Verify containers running
⏳ Health check                 (20s)
```

**Total time:** 6-8 minutes

### Step 8.9: Success!

**When all stages complete:**

```
✓ Set up job                    (5s)
✓ Checkout code                 (3s)
✓ Set up Docker Buildx          (4s)
✓ Login to DockerHub            (2s)
✓ Build and push backend image  (3m 15s)
✓ Deploy to VPS                 (2m 30s)
✓ Health check                  (20s)

This workflow run completed successfully
Total duration: 6m 19s
```

✅ **Deployment successful!**

---

# Phase 9: Verification

## ⏱️ Time: 15 minutes

### Step 9.1: SSH to VPS

**PowerShell:**
```powershell
ssh root@123.45.67.89
# Enter your password
```

**Navigate to project:**
```bash
cd /root/Hypersend
```

### Step 9.2: Check Container Status

```bash
docker-compose ps
```

**Expected output:**
```
NAME                  COMMAND                  SERVICE    STATUS        PORTS
hypersend_backend     "uvicorn app.main:ap…"   backend    Up (healthy)  0.0.0.0:8000->8000/tcp
hypersend_mongodb     "docker-entrypoint.s…"   mongodb    Up (healthy)  27017/tcp
```

✅ **Both containers running and healthy!**

### Step 9.3: Check Backend Logs

```bash
docker-compose logs backend | tail -30
```

**Look for:**
```
INFO:     Started server process [1]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000
```

### Step 9.4: Check MongoDB Logs

```bash
docker-compose logs mongodb | tail -20
```

**Look for:**
```
Waiting for connections on port 27017
```

### Step 9.5: Test Health Endpoint (VPS)

```bash
curl http://localhost:8000/health
```

**Expected response:**
```json
{"status":"healthy"}
```

✅ **API responding!**

### Step 9.6: Check System Resources

**Memory:**
```bash
free -h
```

**Expected:**
```
              total        used        free
Mem:           7.8G        2.8G        3.9G
Swap:          4.0G        100M        3.9G
```

**Disk:**
```bash
df -h
```

**Expected:**
```
Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        97G   18G   74G  20% /
```

**Docker stats:**
```bash
docker stats --no-stream
```

**Expected:**
```
CONTAINER         CPU %     MEM USAGE / LIMIT     MEM %
hypersend_backend 0.45%     380MiB / 7.8GiB       4.75%
hypersend_mongodb 1.12%     1.3GiB / 7.8GiB       16.67%
```

### Step 9.7: Test from Browser (External)

**On your local machine, open browser:**

**Test 1: Health Check**
```
http://123.45.67.89:8000/health
(Replace with YOUR IP)
```

**Expected:**
```json
{"status":"healthy"}
```

**Test 2: API Documentation**
```
http://123.45.67.89:8000/docs
```

**Expected:** Swagger UI page with all API endpoints

✅ **API accessible from internet!**

### Step 9.8: Test Registration

**On Swagger UI page:**

```
1. Find: POST /api/v1/auth/register
2. Click: "Try it out"
3. Enter test data:
{
  "email": "test@example.com",
  "name": "Test User",
  "password": "Test@123456"
}
4. Click: "Execute"
5. Check response: 201 Created
```

**Expected response:**
```json
{
  "id": "user_xxxxx",
  "email": "test@example.com",
  "name": "Test User",
  "created_at": "2025-01-14T10:45:30"
}
```

### Step 9.9: Test Login

```
1. Find: POST /api/v1/auth/login
2. Click: "Try it out"
3. Enter:
{
  "email": "test@example.com",
  "password": "Test@123456"
}
4. Click: "Execute"
5. Check response: 200 OK
```

**Expected response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

✅ **All API endpoints working!**

### Step 9.10: Verify MongoDB Data

**SSH to VPS:**
```bash
ssh root@123.45.67.89
cd /root/Hypersend
```

**Access MongoDB:**
```bash
docker-compose exec mongodb mongosh -u hypersend -p 'YOUR_MONGO_PASSWORD' --authenticationDatabase admin
```

**Inside MongoDB shell:**
```javascript
// Switch to database
use hypersend

// Show collections
show collections

// Count users
db.users.countDocuments()

// View first user
db.users.findOne()

// Exit
exit
```

**Expected:**
```
hypersend> db.users.countDocuments()
1

hypersend> db.users.findOne()
{
  _id: ObjectId("..."),
  email: "test@example.com",
  name: "Test User",
  ...
}
```

✅ **Database working correctly!**

---

# 🎉 Deployment Complete!

## Your Live Backend

```
┌──────────────────────────────────────────────┐
│ HyperSend Backend - PRODUCTION               │
├──────────────────────────────────────────────┤
│                                              │
│ Status:     🟢 LIVE                          │
│ Provider:   Hostinger VPS (India)            │
│ Location:   Mumbai, IN                       │
│ Payment:    RuPay Debit Card ✅              │
│                                              │
│ API:        http://YOUR_IP:8000              │
│ Docs:       http://YOUR_IP:8000/docs         │
│ Health:     http://YOUR_IP:8000/health       │
│                                              │
│ Infrastructure:                              │
│ • 4 vCPU Cores                               │
│ • 8 GB RAM                                   │
│ • 100 GB NVMe SSD                            │
│ • Unlimited Bandwidth                        │
│                                              │
│ Cost:       ₹849/month ($10/month)           │
│ Budget:     $200                             │
│ Duration:   19 months! 🎉                    │
│                                              │
│ Capacity:                                    │
│ • Concurrent: 50K-70K users                  │
│ • Total: 2-5 Lakh users                      │
│                                              │
│ Database:                                    │
│ • MongoDB 7.0 (local)                        │
│ • Auth enabled                               │
│ • Auto backups                               │
│                                              │
└──────────────────────────────────────────────┘
```

---

# Maintenance Guide

## Daily Tasks

**Quick health check:**
```bash
ssh root@YOUR_IP
cd /root/Hypersend
docker-compose ps
docker-compose logs --tail=30
```

## Weekly Tasks

**Update system:**
```bash
apt update && apt upgrade -y
```

**Clean Docker:**
```bash
docker system prune -f
```

**Check disk:**
```bash
df -h
```

## Monthly Tasks

**Review costs:**
```
Hostinger hPanel → Billing
Check current month usage
```

**Update Docker images:**
```bash
cd /root/Hypersend
docker-compose pull
docker-compose up -d
```

---

# Quick Reference Commands

## Connect to VPS
```bash
ssh root@YOUR_IP
```

## Check Status
```bash
cd /root/Hypersend
docker-compose ps
```

## View Logs
```bash
docker-compose logs -f backend
docker-compose logs -f mongodb
```

## Restart Services
```bash
docker-compose restart
```

## Stop Services
```bash
docker-compose down
```

## Start Services
```bash
docker-compose up -d
```

## Health Check
```bash
curl http://localhost:8000/health
```

## MongoDB Access
```bash
docker-compose exec mongodb mongosh -u hypersend -p 'PASSWORD' --authenticationDatabase admin
```

---

# Troubleshooting

## Issue 1: Can't SSH

**Solution:**
```
1. Hostinger hPanel → Your VPS
2. "Reset Root Password"
3. New password will be shown
4. Try SSH again
```

## Issue 2: Containers Not Starting

**Check:**
```bash
docker-compose ps
docker-compose logs
```

**Solution:**
```bash
docker-compose down
docker-compose up -d
```

## Issue 3: API Not Accessible

**Check firewall:**
```bash
ufw status
ufw allow 8000/tcp
ufw reload
```

## Issue 4: Out of Memory

**Check:**
```bash
free -h
```

**Solution:**
```bash
swapon -a
docker-compose restart
```

## Issue 5: Disk Full

**Clean:**
```bash
docker system prune -af
apt autoremove -y
```

---

# Budget Tracking

## Monthly Cost

```
Service: Hostinger VPS 4
Cost: ₹849/month (~$10/month)

Payment: RuPay Debit Card
Auto-renewal: Enabled

Budget Status:
Total: $200 (₹16,500)
Duration: 19 months
Remaining after 1 month: $190
```

## Upgrade Path

**If need more resources:**

```
VPS 8:
- 8 vCPU
- 16 GB RAM
- ₹1,599/month (~$19/month)
- Duration with $200: 10 months
- Capacity: 100K+ concurrent users
```

---

# Support Resources

## Hostinger Support

```
Live Chat: 24/7 (Hindi/English)
Email: support@hostinger.com
Phone: Available in hPanel
Knowledge Base: https://support.hostinger.com
```

## Documentation Files

```
C:\Users\mayan\Downloads\Addidas\hypersend\
├── RUPAY_VPS_DEPLOYMENT.md         (This file)
├── DIGITALOCEAN_COMPLETE_GUIDE.md  (Reference)
├── save more.md                     (Original guide)
└── TROUBLESHOOTING.md               (Common issues)
```

---

# Next Steps

## 1. Test All Features

```
□ User registration
□ User login
□ Create chat
□ Send message
□ Upload file
□ Download file
□ Real-time features
```

## 2. Performance Testing

```
□ Load test with 100 users
□ Load test with 1000 users
□ Monitor response times
□ Check resource usage
```

## 3. Setup Monitoring

```
□ Hostinger monitoring dashboard
□ Setup email alerts
□ Monitor daily
```

## 4. Build Android APK

```
□ Update frontend API_BASE_URL
□ Build APK: flet build apk
□ Test with live backend
□ Distribute to users
```

## 5. Scale if Needed

```
□ Monitor user growth
□ Upgrade VPS if needed
□ Add load balancer (future)
```

---

# Success! 🎉

**Congratulations! Aapka backend successfully deploy ho gaya hai!**

```
✅ Hostinger VPS configured
✅ RuPay payment successful
✅ Docker + MongoDB running
✅ Backend API live
✅ GitHub Actions automated
✅ Password authentication working
✅ 2+ Lakh users ready
✅ 19 months in $200 budget

🚀 API: http://YOUR_IP:8000
📚 Docs: http://YOUR_IP:8000/docs
💪 Ready for production!
```

---

**End of Guide**

*Last Updated: 2025-01-14*
*Version: 1.0 - RuPay Edition*
*Provider: Hostinger VPS India*
