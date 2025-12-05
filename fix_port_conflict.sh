#!/bin/bash
# Fix Docker Compose Port 80 Conflict
# This script helps resolve the "address already in use" error for port 80

set -e

echo "=========================================="
echo "Hypersend Docker Port Conflict Fix"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to find process using port
find_port_user() {
    local port=$1
    echo -e "${YELLOW}[INFO] Checking what's using port $port...${NC}"
    
    if command -v lsof &> /dev/null; then
        lsof -i :$port || echo "No process found using port $port"
    elif command -v netstat &> /dev/null; then
        netstat -tlnp | grep ":$port " || echo "No process found using port $port"
    else
        echo -e "${YELLOW}[WARN] Cannot check port usage (lsof/netstat not available)${NC}"
    fi
}

# Function to free port
free_port() {
    local port=$1
    echo -e "${YELLOW}[ACTION] Attempting to free port $port...${NC}"
    
    # Try to find and kill process using the port
    if command -v fuser &> /dev/null; then
        echo -e "${YELLOW}[INFO] Found 'fuser' command, using it to release port $port${NC}"
        sudo fuser -k $port/tcp 2>/dev/null || true
        sleep 2
        echo -e "${GREEN}[OK] Port $port should now be free${NC}"
    else
        echo -e "${YELLOW}[WARN] 'fuser' command not available${NC}"
        echo -e "${YELLOW}[ACTION] Please manually kill the process using port $port${NC}"
    fi
}

# Main fix
echo -e "${YELLOW}[STEP 1] Stopping current Docker containers...${NC}"
docker compose down 2>/dev/null || echo "No containers running"
sleep 2

echo -e "${GREEN}[OK] Containers stopped${NC}"
echo ""

echo -e "${YELLOW}[STEP 2] Checking port 80 status...${NC}"
find_port_user 80
echo ""

# If port 80 is still in use, try to free it
if netstat -tlnp 2>/dev/null | grep -q ":80 " || lsof -i :80 &>/dev/null; then
    echo -e "${YELLOW}[STEP 3] Port 80 is in use, attempting to free it...${NC}"
    free_port 80
    echo ""
fi

# Verify port 80 is free
echo -e "${YELLOW}[STEP 4] Verifying port 80 is free...${NC}"
if netstat -tlnp 2>/dev/null | grep -q ":80 " || lsof -i :80 &>/dev/null; then
    echo -e "${RED}[ERROR] Port 80 is still in use!${NC}"
    echo -e "${YELLOW}[SOLUTION] Please manually kill the process using port 80:${NC}"
    echo "    sudo lsof -i :80"
    echo "    sudo kill -9 <PID>"
    exit 1
else
    echo -e "${GREEN}[OK] Port 80 is free!${NC}"
fi
echo ""

echo -e "${YELLOW}[STEP 5] Pulling latest Docker images...${NC}"
docker compose pull
echo -e "${GREEN}[OK] Images pulled${NC}"
echo ""

echo -e "${YELLOW}[STEP 6] Building and starting containers...${NC}"
docker compose up -d --build
echo ""

echo -e "${YELLOW}[STEP 7] Waiting for containers to stabilize...${NC}"
sleep 5

echo -e "${YELLOW}[STEP 8] Checking container status...${NC}"
docker compose ps

echo ""
echo -e "${GREEN}=========================================="
echo "Docker Compose Fix Complete!"
echo "==========================================${NC}"
echo ""
echo -e "${GREEN}Access your app at:${NC}"
echo "  - Frontend: http://localhost"
echo "  - API: http://localhost/api/v1/docs"
echo "  - MongoDB: mongodb://admin:changeme@localhost:27017"
echo ""
echo -e "${YELLOW}[TIP] If you see nginx still failing, check:${NC}"
echo "  1. nginx.conf is correct"
echo "  2. Backend is running: docker compose logs backend"
echo "  3. Frontend is running: docker compose logs frontend"
echo ""
