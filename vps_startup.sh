#!/bin/bash
# 🚀 HYPERSEND EMERGENCY STARTUP SCRIPT
# Run this if backend shows "Unable to connect" error
# Usage: bash vps_startup.sh

set -e

echo "╔════════════════════════════════════════════════════╗"
echo "║  HYPERSEND EMERGENCY STARTUP                      ║"
echo "║  Fixes: Backend Connection Error (139.59.82.105)  ║"
echo "╚════════════════════════════════════════════════════╝"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

VPS_IP="139.59.82.105"
PROJECT_ROOT="/root/Hypersend"

# Step 1: Verify root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}❌ This script must be run as root${NC}"
    echo "   Run: sudo bash vps_startup.sh"
    exit 1
fi
echo -e "${GREEN}✅ Running as root${NC}"

# Step 2: Check Docker
echo ""
echo -e "${BLUE}[1/8] Checking Docker installation...${NC}"
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker not found${NC}"
    exit 1
fi
docker_version=$(docker --version)
echo -e "${GREEN}✅ Docker installed: $docker_version${NC}"

# Step 3: Check Docker Compose
echo ""
echo -e "${BLUE}[2/8] Checking Docker Compose...${NC}"
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}❌ Docker Compose not found${NC}"
    exit 1
fi
compose_version=$(docker-compose --version)
echo -e "${GREEN}✅ Docker Compose installed: $compose_version${NC}"

# Step 4: Navigate to project
echo ""
echo -e "${BLUE}[3/8] Checking project directory...${NC}"
if [ ! -d "$PROJECT_ROOT" ]; then
    echo -e "${YELLOW}⚠️  Project not found at $PROJECT_ROOT${NC}"
    echo "   Cloning from GitHub..."
    git clone https://github.com/Mayankvlog/Hypersend.git "$PROJECT_ROOT"
fi
cd "$PROJECT_ROOT"
echo -e "${GREEN}✅ Project directory: $PROJECT_ROOT${NC}"

# Step 5: Stop existing services
echo ""
echo -e "${BLUE}[4/8] Stopping existing services...${NC}"
docker-compose down 2>/dev/null || true
sleep 2
echo -e "${GREEN}✅ Services stopped${NC}"

# Step 6: Create .env if missing
echo ""
echo -e "${BLUE}[5/8] Checking environment configuration...${NC}"
if [ ! -f ".env" ]; then
    echo -e "${YELLOW}⚠️  .env file not found, creating...${NC}"
    cat > .env << 'EOF'
# Zaply Application Configuration
# Auto-generated for VPS deployment

SECRET_KEY=72hf2XTyuBXOGVbpgS9iyJKSePUTwLcLQL_DsaC4yqk
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=30

MONGODB_URI=mongodb://hypersend:Mayank%40%2303@139.59.82.105:27017/hypersend?authSource=admin
MONGO_USER=hypersend
MONGO_PASSWORD=Mayank@#03

API_HOST=0.0.0.0
API_PORT=8000
API_BASE_URL=http://139.59.82.105:8000
DEBUG=False

STORAGE_MODE=local
DATA_ROOT=/data
CHUNK_SIZE=4194304
MAX_FILE_SIZE_BYTES=42949672960
MAX_PARALLEL_CHUNKS=4
UPLOAD_EXPIRE_HOURS=24
FILE_RETENTION_HOURS=0

RATE_LIMIT_PER_USER=100
RATE_LIMIT_WINDOW_SECONDS=60

VPS_IP=139.59.82.105
NGINX_PORT=8080
NGINX_PORT_SSL=8443
EOF
    echo -e "${GREEN}✅ .env created${NC}"
else
    echo -e "${GREEN}✅ .env exists${NC}"
fi

# Step 7: Pull latest images
echo ""
echo -e "${BLUE}[6/8] Pulling latest Docker images...${NC}"
docker-compose pull
echo -e "${GREEN}✅ Images pulled${NC}"

# Step 8: Start services
echo ""
echo -e "${BLUE}[7/8] Starting services...${NC}"
docker-compose up -d
echo -e "${GREEN}✅ Services started${NC}"

# Wait for startup
echo ""
echo -e "${BLUE}[8/8] Waiting for services to initialize...${NC}"
sleep 10

# Health checks
echo ""
echo -e "${YELLOW}Running health checks...${NC}"
echo ""

# Check backend
echo -n "Backend API: "
if curl -sf http://127.0.0.1:8000/health > /dev/null 2>&1; then
    echo -e "${GREEN}✅ RESPONDING${NC}"
else
    echo -e "${RED}❌ NOT RESPONDING${NC}"
    echo "   View logs: docker-compose logs backend"
fi

# Check MongoDB
echo -n "MongoDB: "
if docker-compose exec -T mongodb mongosh --eval "db.adminCommand('ping')" > /dev/null 2>&1; then
    echo -e "${GREEN}✅ RESPONDING${NC}"
else
    echo -e "${RED}❌ NOT RESPONDING${NC}"
    echo "   View logs: docker-compose logs mongodb"
fi

# Check Nginx
echo -n "Nginx: "
if curl -sf http://127.0.0.1:8080/health > /dev/null 2>&1; then
    echo -e "${GREEN}✅ RESPONDING${NC}"
else
    echo -e "${RED}❌ NOT RESPONDING${NC}"
    echo "   View logs: docker-compose logs nginx"
fi

echo ""
echo "╔════════════════════════════════════════════════════╗"
echo -e "║${GREEN}  STARTUP COMPLETE${NC}                              ║"
echo "╚════════════════════════════════════════════════════╝"
echo ""
echo "Service Status:"
docker-compose ps
echo ""
echo "📋 Service Logs:"
echo "   Backend: docker-compose logs backend"
echo "   MongoDB: docker-compose logs mongodb"
echo "   Nginx:   docker-compose logs nginx"
echo ""
echo "🌐 Access your services:"
echo "   API:  http://$VPS_IP:8000"
echo "   Web:  http://$VPS_IP:8080"
echo ""
echo "📊 Health Check:"
echo "   Backend: curl http://127.0.0.1:8000/health"
echo "   Nginx:   curl http://127.0.0.1:8080/health"
echo ""
echo "⚙️  Enable Auto-Start on Boot:"
echo "   sudo systemctl enable hypersend"
echo ""
