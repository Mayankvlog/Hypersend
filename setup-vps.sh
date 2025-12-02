#!/bin/bash

# ============================================================
# 🚀 ZAPLY COMPLETE VPS SETUP & DEPLOYMENT
# ============================================================
# This script sets up Zaply from scratch on a fresh VPS
#
# Usage: curl -fsSL https://raw.githubusercontent.com/Mayankvlog/Hypersend/main/setup-vps.sh | bash
# Or: bash setup-vps.sh
#
# ============================================================

set -e

echo ""
echo "╔════════════════════════════════════════════════════════╗"
echo "║          🚀 ZAPLY VPS COMPLETE SETUP                   ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ============================================================
# Check if running as root
# ============================================================
if [ "$EUID" -ne 0 ]; then
   echo -e "${RED}✗${NC} This script must be run as root"
   echo "   Run with: sudo bash setup-vps.sh"
   exit 1
fi

echo -e "${GREEN}✓${NC} Running as root"
echo ""

# ============================================================
# Step 1: Check if Git is installed
# ============================================================
echo -e "${BLUE}[1/7]${NC} Checking dependencies..."
if ! command -v git &> /dev/null; then
   echo -e "${YELLOW}Installing git...${NC}"
   apt-get update -qq
   apt-get install -y git curl
fi
echo -e "${GREEN}✓${NC} Git is installed"

# ============================================================
# Step 2: Check if Docker is installed
# ============================================================
if ! command -v docker &> /dev/null; then
   echo -e "${YELLOW}Installing Docker...${NC}"
   curl -fsSL https://get.docker.com -o get-docker.sh
   sh get-docker.sh
   rm get-docker.sh
fi
echo -e "${GREEN}✓${NC} Docker is installed"

# ============================================================
# Step 3: Check if Docker Compose is installed
# ============================================================
if ! command -v docker-compose &> /dev/null; then
   echo -e "${YELLOW}Installing Docker Compose...${NC}"
   curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
   chmod +x /usr/local/bin/docker-compose
fi
echo -e "${GREEN}✓${NC} Docker Compose is installed"
echo ""

# ============================================================
# Step 4: Clone or update repository
# ============================================================
echo -e "${BLUE}[2/7]${NC} Cloning repository..."
REPO_DIR="/hypersend/Hypersend"

if [ -d "$REPO_DIR" ]; then
   echo "Repository already exists. Updating..."
   cd "$REPO_DIR"
   git pull origin main
else
   echo "Cloning repository..."
   mkdir -p /hypersend
   git clone https://github.com/Mayankvlog/Hypersend.git "$REPO_DIR"
   cd "$REPO_DIR"
fi

echo -e "${GREEN}✓${NC} Repository ready at $REPO_DIR"
echo ""

# ============================================================
# Step 5: Create .env file
# ============================================================
echo -e "${BLUE}[3/7]${NC} Setting up environment..."

if [ ! -f ".env" ]; then
   cp .env.example .env
   echo -e "${GREEN}✓${NC} Created .env file"
else
   echo -e "${GREEN}✓${NC} .env file already exists"
fi
echo ""

# ============================================================
# Step 6: Pull Docker images
# ============================================================
echo -e "${BLUE}[4/7]${NC} Pulling Docker images..."
docker-compose pull
echo -e "${GREEN}✓${NC} Images pulled"
echo ""

# ============================================================
# Step 7: Start services
# ============================================================
echo -e "${BLUE}[5/7]${NC} Starting services..."
docker-compose down 2>/dev/null || true
docker-compose up -d
echo -e "${GREEN}✓${NC} Services started"
echo ""

# ============================================================
# Step 8: Wait and verify
# ============================================================
echo -e "${BLUE}[6/7]${NC} Waiting for services to be ready..."
sleep 5

BACKEND_RUNNING=$(docker-compose ps | grep hypersend_backend | grep -c "Up" || echo "0")
FRONTEND_RUNNING=$(docker-compose ps | grep hypersend_frontend | grep -c "Up" || echo "0")
MONGODB_RUNNING=$(docker-compose ps | grep hypersend_mongodb | grep -c "Up" || echo "0")

if [ "$BACKEND_RUNNING" == "1" ] && [ "$FRONTEND_RUNNING" == "1" ] && [ "$MONGODB_RUNNING" == "1" ]; then
   echo -e "${GREEN}✓${NC} All services running"
else
   echo -e "${RED}✗${NC} Some services failed to start"
   echo ""
   docker-compose ps
   echo ""
   echo "Checking backend logs:"
   docker logs hypersend_backend --tail=20
   exit 1
fi
echo ""

# ============================================================
# Step 9: Display summary
# ============================================================
echo -e "${BLUE}[7/7]${NC} Deployment complete"
echo ""
echo "╔════════════════════════════════════════════════════════╗"
echo "║         ✅ ZAPLY SUCCESSFULLY DEPLOYED                 ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

VPS_IP=$(hostname -I | awk '{print $1}')
echo "Access your application:"
echo ""
echo "  📱 API:         http://$VPS_IP:8000"
echo "  📖 API Docs:    http://$VPS_IP:8000/docs"
echo "  📖 API ReDoc:   http://$VPS_IP:8000/redoc"
echo "  🖥️  Frontend:    http://$VPS_IP:8550"
echo ""
echo "Configuration:"
echo "  📁 Project:     $REPO_DIR"
echo "  ⚙️  Config:      .env"
echo "  🐳 Compose:     docker-compose.yml"
echo ""
echo "Useful commands:"
echo "  View status:    docker-compose ps"
echo "  View logs:      docker logs -f hypersend_backend"
echo "  Stop services:  docker-compose down"
echo "  Restart:        docker-compose restart"
echo ""
echo "Documentation:"
echo "  • QUICK_DEPLOY.md     - Quick deployment guide"
echo "  • VPS_DEBUG_GUIDE.md  - Troubleshooting guide"
echo "  • README.md           - Full documentation"
echo ""
