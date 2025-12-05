#!/bin/bash
# 🚀 Hypersend Production Deployment Script
# Run this script on VPS: bash deploy.sh

set -e

echo "================================"
echo "🚀 Hypersend Production Deployment"
echo "================================"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

VPS_IP="139.59.82.105"
DEPLOY_DIR="/root/Hypersend"

echo -e "${YELLOW}[1/6] Checking prerequisites...${NC}"
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker not found. Please install Docker first.${NC}"
    exit 1
fi
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}❌ Docker Compose not found. Please install Docker Compose first.${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Prerequisites OK${NC}"

echo -e "${YELLOW}[2/6] Cloning/Updating repository...${NC}"
if [ -d "$DEPLOY_DIR" ]; then
    cd "$DEPLOY_DIR"
    git pull origin main
else
    git clone https://github.com/Mayankvlog/Hypersend.git "$DEPLOY_DIR"
    cd "$DEPLOY_DIR"
fi
echo -e "${GREEN}✅ Repository updated${NC}"

echo -e "${YELLOW}[3/6] Setting up environment...${NC}"
if [ ! -f ".env.production" ]; then
    echo -e "${YELLOW}Creating .env.production...${NC}"
    cp .env.production.example .env.production
    echo -e "${RED}⚠️  IMPORTANT: Edit .env.production with your settings:${NC}"
    echo "   nano .env.production"
    echo ""
    echo "   Key settings to update:"
    echo "   - MONGO_USER=hypersend"
    echo "   - MONGO_PASSWORD=Mayank@#03"
    echo "   - SECRET_KEY=<generate-new-key>"
    echo "   - VPS_IP=139.59.82.105"
    echo ""
    exit 0
fi
echo -e "${GREEN}✅ Environment file exists${NC}"

echo -e "${YELLOW}[4/6] Pulling latest images...${NC}"
docker-compose pull
echo -e "${GREEN}✅ Images pulled${NC}"

echo -e "${YELLOW}[5/6] Starting services...${NC}"
docker-compose down || true
docker-compose up -d
echo -e "${GREEN}✅ Services started${NC}"

echo -e "${YELLOW}[6/6] Verifying deployment...${NC}"
sleep 5

# Check if backend is responding
if curl -sf http://localhost:8000/health > /dev/null; then
    echo -e "${GREEN}✅ Backend is healthy${NC}"
else
    echo -e "${RED}⚠️  Backend health check failed. Checking logs...${NC}"
    docker-compose logs backend | tail -20
fi

# Check if nginx is responding
if curl -sf http://localhost:8080/health > /dev/null; then
    echo -e "${GREEN}✅ Nginx is healthy${NC}"
else
    echo -e "${RED}⚠️  Nginx health check failed.${NC}"
fi

echo ""
echo "================================"
echo -e "${GREEN}✅ Deployment complete!${NC}"
echo "================================"
echo ""
echo "Service Status:"
docker-compose ps
echo ""
echo "Access your services at:"
echo "  - API: http://${VPS_IP}:8000"
echo "  - Web: http://${VPS_IP}:8080"
echo "  - Health: http://${VPS_IP}:8080/health"
echo ""
echo "View logs:"
echo "  docker-compose logs -f backend"
echo "  docker-compose logs -f mongodb"
echo "  docker-compose logs -f nginx"
echo ""
echo "Update code:"
echo "  cd $DEPLOY_DIR && git pull origin main && docker-compose up -d"
echo ""
