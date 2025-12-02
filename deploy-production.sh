#!/bin/bash

# ============================================================
# 🚀 ZAPLY PRODUCTION DEPLOYMENT SCRIPT
# ============================================================
# Run this on your VPS to deploy Zaply with proper SECRET_KEY
#
# Usage: bash deploy-production.sh
#
# This script will:
# 1. Pull latest code from GitHub
# 2. Generate/use secure SECRET_KEY
# 3. Set up production environment
# 4. Start all services with Docker Compose
# ============================================================

set -e  # Exit on any error

echo ""
echo "╔════════════════════════════════════════════════════════╗"
echo "║       🚀 ZAPLY PRODUCTION DEPLOYMENT SCRIPT            ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ============================================================
# Step 1: Check if running as root
# ============================================================
if [ "$EUID" -eq 0 ]; then
   echo -e "${GREEN}✓${NC} Running as root"
else
   echo -e "${RED}✗${NC} This script must be run as root"
   echo "   Run with: sudo bash deploy-production.sh"
   exit 1
fi

# ============================================================
# Step 2: Navigate to project directory
# ============================================================
PROJECT_DIR="/hypersend/Hypersend"
if [ ! -d "$PROJECT_DIR" ]; then
   echo -e "${RED}✗${NC} Project directory not found: $PROJECT_DIR"
   exit 1
fi

cd "$PROJECT_DIR"
echo -e "${GREEN}✓${NC} Working directory: $(pwd)"
echo ""

# ============================================================
# Step 2.5: Ensure Docker & Docker Compose are installed
# ============================================================
if ! command -v docker &> /dev/null; then
   echo -e "${RED}✗${NC} Docker is not installed on this VPS."
   echo "   Fix: run setup-vps.sh first to install Docker and Docker Compose:"
   echo "        curl -fsSL https://raw.githubusercontent.com/Mayankvlog/Hypersend/main/setup-vps.sh | bash"
   exit 1
fi

if ! command -v docker-compose &> /dev/null; then
   echo -e "${RED}✗${NC} docker-compose is not installed on this VPS."
   echo "   Fix: run setup-vps.sh first to install Docker Compose:"
   echo "        curl -fsSL https://raw.githubusercontent.com/Mayankvlog/Hypersend/main/setup-vps.sh | bash"
   exit 1
fi

# ============================================================
# Step 3: Pull latest code from GitHub
# ============================================================
echo -e "${BLUE}[1/6]${NC} Pulling latest code from GitHub..."
git pull origin main
echo -e "${GREEN}✓${NC} Code pulled successfully"
echo ""

# ============================================================
# Step 4: Check if .env.production exists
# ============================================================
echo -e "${BLUE}[2/6]${NC} Checking production environment file..."
if [ ! -f ".env.production" ]; then
   echo -e "${YELLOW}⚠${NC}  .env.production not found. Creating from template..."
   cp .env.production.example .env.production
   echo -e "${YELLOW}!${NC}  EDIT .env.production NOW with your values:"
   echo ""
   echo "   nano .env.production"
   echo ""
   echo "   Required changes:"
   echo "   - MONGO_PASSWORD: Set a strong password"
   echo "   - SECRET_KEY: Already pre-filled with secure key"
   echo "   - VPS_IP: Set to your server IP (139.59.82.105)"
   echo ""
   echo "   Then run this script again."
   exit 1
fi
echo -e "${GREEN}✓${NC} .env.production exists"

# ============================================================
# Step 5: Load environment variables from .env.production
# ============================================================
echo -e "${BLUE}[3/6]${NC} Loading environment variables..."
export $(cat .env.production | grep -v '#' | xargs)

# Verify SECRET_KEY is set
if [ -z "$SECRET_KEY" ]; then
   echo -e "${RED}✗${NC} SECRET_KEY not set in .env.production"
   exit 1
fi

if [[ "$SECRET_KEY" == *"YOUR_GENERATED"* ]] || [[ "$SECRET_KEY" == "" ]]; then
   echo -e "${RED}✗${NC} SECRET_KEY is still invalid. Edit .env.production:"
   echo ""
   echo "   nano .env.production"
   echo ""
   exit 1
fi

echo -e "${GREEN}✓${NC} SECRET_KEY loaded (length: ${#SECRET_KEY} chars)"
echo ""

# ============================================================
# Step 6: Pull latest Docker images
# ============================================================
echo -e "${BLUE}[4/6]${NC} Pulling latest Docker images..."
docker-compose pull
echo -e "${GREEN}✓${NC} Images pulled successfully"
echo ""

# ============================================================
# Step 7: Start services
# ============================================================
echo -e "${BLUE}[5/6]${NC} Starting services with docker-compose..."
docker-compose down 2>/dev/null || true
docker-compose up -d
echo -e "${GREEN}✓${NC} Services started"
echo ""

# ============================================================
# Step 8: Wait for services and verify
# ============================================================
echo -e "${BLUE}[6/6]${NC} Verifying services..."
sleep 5

# Check if containers are running
BACKEND_STATUS=$(docker-compose ps | grep hypersend_backend | awk '{print $6}')
FRONTEND_STATUS=$(docker-compose ps | grep hypersend_frontend | awk '{print $6}')
MONGODB_STATUS=$(docker-compose ps | grep hypersend_mongodb | awk '{print $6}')

if [[ $BACKEND_STATUS == *"Up"* ]] && [[ $FRONTEND_STATUS == *"Up"* ]] && [[ $MONGODB_STATUS == *"Up"* ]]; then
   echo -e "${GREEN}✓${NC} All services running"
else
   echo -e "${RED}✗${NC} Some services failed to start"
   echo ""
   echo "Backend: $BACKEND_STATUS"
   echo "Frontend: $FRONTEND_STATUS"
   echo "MongoDB: $MONGODB_STATUS"
   echo ""
   echo "Check logs with:"
   echo "  docker logs hypersend_backend"
   echo "  docker logs hypersend_frontend"
   echo "  docker logs hypersend_mongodb"
   exit 1
fi

echo ""
echo "╔════════════════════════════════════════════════════════╗"
echo "║         ✅ DEPLOYMENT SUCCESSFUL                       ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""
echo "Your Zaply application is now running!"
echo ""
VPS_IP=$(grep "VPS_IP=" .env.production | cut -d'=' -f2)
echo "Access points:"
echo "  📱 API: http://$VPS_IP:8000"
echo "  📖 API Docs: http://$VPS_IP:8000/docs"
echo "  🖥️  Frontend: http://$VPS_IP:8550"
echo ""
echo "Monitor logs:"
echo "  docker logs -f hypersend_backend"
echo "  docker logs -f hypersend_frontend"
echo "  docker logs -f hypersend_mongodb"
echo ""
echo "Stop services:"
echo "  docker-compose down"
echo ""
