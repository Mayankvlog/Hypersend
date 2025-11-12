#!/bin/bash

# ============================================================================
# HyperSend Production Deployment - Quick Setup Script
# For DigitalOcean VPS with GitHub Actions & DockerHub
# ============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

print_header() {
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC} $1"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_step() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

# ============================================================================
# MAIN SETUP
# ============================================================================

print_header "HyperSend Production Deployment Setup"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    print_error "This script must be run as root"
    echo "Run: sudo bash QUICK_SETUP.sh"
    exit 1
fi

# ============================================================================
# STEP 1: SYSTEM UPDATES
# ============================================================================

print_header "Step 1: System Updates"

print_info "Updating system packages..."
apt update && apt upgrade -y
print_step "System updated"

# ============================================================================
# STEP 2: INSTALL DOCKER
# ============================================================================

print_header "Step 2: Installing Docker"

if command -v docker &> /dev/null; then
    print_step "Docker already installed: $(docker --version)"
else
    print_info "Installing Docker..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    systemctl start docker
    systemctl enable docker
    print_step "Docker installed: $(docker --version)"
fi

# ============================================================================
# STEP 3: INSTALL DOCKER COMPOSE
# ============================================================================

print_header "Step 3: Installing Docker Compose"

if command -v docker-compose &> /dev/null; then
    print_step "Docker Compose already installed: $(docker-compose --version)"
else
    print_info "Installing Docker Compose..."
    apt install docker-compose -y
    print_step "Docker Compose installed: $(docker-compose --version)"
fi

# ============================================================================
# STEP 4: CREATE SWAP MEMORY
# ============================================================================

print_header "Step 4: Creating Swap Memory"

if [ -f /swapfile ]; then
    print_step "Swap already exists"
else
    print_info "Creating 4GB swap file..."
    fallocate -l 4G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
    print_step "Swap created (4GB)"
fi

# ============================================================================
# STEP 5: SETUP FIREWALL
# ============================================================================

print_header "Step 5: Setting Up Firewall"

if ! command -v ufw &> /dev/null; then
    print_info "Installing UFW..."
    apt install ufw -y
fi

print_info "Configuring firewall rules..."
ufw allow 22/tcp    # SSH
ufw allow 80/tcp    # HTTP
ufw allow 443/tcp   # HTTPS
ufw allow 8000/tcp  # Backend API
ufw allow 8550/tcp  # Frontend
ufw --force enable
print_step "Firewall configured"

# ============================================================================
# STEP 6: CREATE PROJECT DIRECTORY
# ============================================================================

print_header "Step 6: Creating Project Directory"

if [ -d /root/Hypersend ]; then
    print_step "Project directory already exists"
else
    print_info "Creating /root/Hypersend..."
    mkdir -p /root/Hypersend
    print_step "Project directory created"
fi

cd /root/Hypersend

# ============================================================================
# STEP 7: CLONE REPOSITORY
# ============================================================================

print_header "Step 7: Repository Setup"

if [ -d .git ]; then
    print_info "Repository already cloned, pulling latest..."
    git pull origin main
    print_step "Repository updated"
else
    print_warning "Repository not cloned yet"
    print_info "You need to clone your GitHub repository:"
    echo ""
    echo "  cd /root/Hypersend"
    echo "  git clone https://github.com/YOUR_USERNAME/hypersend.git ."
    echo ""
fi

# ============================================================================
# STEP 8: CREATE ENVIRONMENT FILE
# ============================================================================

print_header "Step 8: Environment Configuration"

if [ -f .env ]; then
    print_step ".env file already exists"
else
    print_info "Creating .env file..."
    cat > .env << 'EOF'
# MongoDB Atlas Connection
MONGODB_URI=mongodb+srv://hypersend_user:YOUR_PASSWORD@cluster0.xxxxx.mongodb.net/hypersend?retryWrites=true&w=majority

# Security (generate with: openssl rand -hex 32)
SECRET_KEY=your-super-secret-key-min-32-characters-long-here

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
API_BASE_URL=http://YOUR_VPS_IP:8000

# Production Settings
DEBUG=False
ENVIRONMENT=production

# Performance Tuning
CHUNK_SIZE=8388608
MAX_PARALLEL_CHUNKS=8
MAX_FILE_SIZE_BYTES=107374182400

# Rate Limiting
RATE_LIMIT_PER_USER=500
RATE_LIMIT_WINDOW_SECONDS=60

# Storage
DATA_ROOT=/data
STORAGE_MODE=local

# DockerHub
DOCKERHUB_USERNAME=your-dockerhub-username
EOF
    print_step ".env file created"
    print_warning "⚠️  IMPORTANT: Edit .env file with your actual values:"
    echo "   nano /root/Hypersend/.env"
fi

# ============================================================================
# STEP 9: CREATE MONITORING SCRIPTS
# ============================================================================

print_header "Step 9: Creating Monitoring Scripts"

# Monitor script
cat > /root/monitor.sh << 'EOF'
#!/bin/bash

echo "╔════════════════════════════════════════════════════════════╗"
echo "║         HyperSend Production Monitoring Dashboard          ║"
echo "╚══════════════════════════════════��═════════════════════════╝"
echo ""

echo "📊 SYSTEM RESOURCES"
echo "─────────────────────────────────────────────────────────────"
free -h | grep -E "Mem|Swap"
echo ""
df -h | grep -E "Filesystem|/dev/vda"
echo ""

echo "🐳 DOCKER CONTAINERS"
echo "─────────────────────────────────────────────────────────────"
cd /root/Hypersend
docker-compose ps
echo ""

echo "⚙️  DOCKER STATS"
echo "─────────────────────────────────────────────────────────────"
docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}"
echo ""

echo "🌐 ACTIVE CONNECTIONS"
echo "─────────────────────────────────────────────────────���───────"
echo "Backend (8000): $(netstat -an 2>/dev/null | grep :8000 | wc -l) connections"
echo "Frontend (8550): $(netstat -an 2>/dev/null | grep :8550 | wc -l) connections"
echo ""

echo "📝 RECENT ERRORS"
echo "─────────────────────────────────────────────────────────────"
docker-compose logs --tail=5 backend | grep -i error || echo "✅ No errors"
echo ""

echo "✅ Last updated: $(date)"
EOF

chmod +x /root/monitor.sh
print_step "Monitor script created: /root/monitor.sh"

# Health check script
cat > /root/health_check.sh << 'EOF'
#!/bin/bash

echo "🏥 HyperSend Health Check"
echo "─────────────────────────────────────────────────────────────"

cd /root/Hypersend

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

echo "────────────────────────────��────────────────────────────────"
echo "✅ Health check completed at $(date)"
EOF

chmod +x /root/health_check.sh
print_step "Health check script created: /root/health_check.sh"

# ============================================================================
# STEP 10: INSTALL ADDITIONAL TOOLS
# ============================================================================

print_header "Step 10: Installing Additional Tools"

print_info "Installing monitoring tools..."
apt install htop iotop nethogs curl wget git -y
print_step "Tools installed"

# ============================================================================
# STEP 11: SETUP CRON JOBS
# ============================================================================

print_header "Step 11: Setting Up Cron Jobs"

# Check if cron job already exists
if crontab -l 2>/dev/null | grep -q "health_check.sh"; then
    print_step "Health check cron job already exists"
else
    print_info "Adding health check cron job (daily at 2 AM)..."
    (crontab -l 2>/dev/null; echo "0 2 * * * /root/health_check.sh >> /root/health_check.log 2>&1") | crontab -
    print_step "Cron job added"
fi

# ============================================================================
# STEP 12: DISPLAY SUMMARY
# ============================================================================

print_header "Setup Complete! 🎉"

echo -e "${GREEN}All prerequisites installed successfully!${NC}"
echo ""
echo "📋 Next Steps:"
echo ""
echo "1️⃣  Clone your GitHub repository:"
echo "   cd /root/Hypersend"
echo "   git clone https://github.com/YOUR_USERNAME/hypersend.git ."
echo ""
echo "2️⃣  Edit environment configuration:"
echo "   nano /root/Hypersend/.env"
echo "   - Add MongoDB URI"
echo "   - Add SECRET_KEY"
echo "   - Add your VPS IP"
echo "   - Add DockerHub username"
echo ""
echo "3️⃣  Configure GitHub Secrets:"
echo "   Go to: GitHub Repository → Settings → Secrets and variables → Actions"
echo "   Add these 6 secrets:"
echo "   - DOCKERHUB_USERNAME"
echo "   - DOCKERHUB_TOKEN"
echo "   - VPS_HOST (your VPS IP)"
echo "   - VPS_USER (root)"
echo "   - VPS_PASSWORD"
echo "   - MONGODB_URI"
echo ""
echo "4️⃣  Push code to trigger deployment:"
echo "   git add ."
echo "   git commit -m 'Production deployment setup'"
echo "   git push origin main"
echo ""
echo "5️⃣  Monitor deployment:"
echo "   GitHub Repository → Actions tab"
echo ""
echo "6️⃣  Verify deployment:"
echo "   /root/health_check.sh"
echo "   /root/monitor.sh"
echo ""
echo "📊 Useful Commands:"
echo "   - Monitor: /root/monitor.sh"
echo "   - Health Check: /root/health_check.sh"
echo "   - View Logs: docker-compose logs -f backend"
echo "   - Restart Services: docker-compose restart"
echo "   - Stop Services: docker-compose down"
echo "   - Start Services: docker-compose up -d"
echo ""
echo "🌐 Access Points (after deployment):"
echo "   - API: http://YOUR_VPS_IP:8000"
echo "   - Docs: http://YOUR_VPS_IP:8000/docs"
echo "   - Health: http://YOUR_VPS_IP:8000/health"
echo ""
echo "📚 Documentation:"
echo "   - Full Guide: /root/Hypersend/DEPLOYMENT_GUIDE_COMPLETE.md"
echo "   - Production Guide: /root/Hypersend/PRODUCTION_DEPLOYMENT.md"
echo ""
echo -e "${GREEN}✅ Your VPS is ready for production deployment!${NC}"
echo ""
