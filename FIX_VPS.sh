#!/bin/bash

# ============================================================
# VPS FIX SCRIPT - Run this to fix MongoDB & Backend issues
# ============================================================
# Location: /hypersend/Hypersend/FIX_VPS.sh
# Usage: bash FIX_VPS.sh
# ============================================================

set -e  # Exit on any error

echo "====================================================================="
echo "HYPERSEND VPS FIX SCRIPT"
echo "====================================================================="
echo ""

# Pull latest changes from GitHub
echo "[1/8] Pulling latest changes from GitHub..."
cd /hypersend/Hypersend
git pull origin main
echo "✓ Done"
echo ""

# Stop local MongoDB service to free port 27017
echo "[2/8] Stopping local MongoDB service..."
sudo systemctl stop mongod 2>/dev/null || echo "  (mongod not running)"
sudo systemctl disable mongod 2>/dev/null || echo "  (mongod not enabled)"
echo "✓ Done"
echo ""

# Kill any process using port 27017
echo "[3/8] Killing any process using port 27017..."
sudo lsof -ti :27017 | xargs -r sudo kill -9 2>/dev/null || echo "  (No process to kill)"
echo "✓ Done"
echo ""

# Stop and remove all containers
echo "[4/8] Stopping Docker containers..."
docker compose down -v 2>/dev/null || echo "  (No containers running)"
echo "✓ Done"
echo ""

# Remove MongoDB data volumes if they exist
echo "[5/8] Cleaning up Docker volumes..."
docker volume rm hypersend_mongodb_data 2>/dev/null || echo "  (Volume already removed)"
docker volume rm hypersend_mongodb_config 2>/dev/null || echo "  (Volume already removed)"
echo "✓ Done"
echo ""

# Build and start services
echo "[6/8] Building and starting Docker services..."
docker compose up -d --build
echo "✓ Done - Waiting for services to start..."
echo ""

# Wait for services to be healthy
echo "[7/8] Waiting for services to be healthy (60 seconds)..."
sleep 60
echo "✓ Done"
echo ""

# Check status
echo "[8/8] Checking service status..."
echo ""
docker compose ps
echo ""
echo "====================================================================="
echo "TESTING CONNECTIVITY"
echo "====================================================================="
echo ""

# Test local connectivity
echo "Testing local backend..."
if curl -s http://localhost:8000/health > /dev/null; then
    echo "✓ Backend responding locally"
else
    echo "⚠ Backend not responding locally yet - may still be starting"
fi
echo ""

# Test MongoDB connectivity from backend
echo "Checking backend logs for MongoDB connection..."
docker compose logs backend --tail=20
echo ""

echo "====================================================================="
echo "VERIFICATION STEPS:"
echo "====================================================================="
echo ""
echo "1. Check all services are healthy:"
echo "   docker compose ps"
echo ""
echo "2. Check MongoDB is running:"
echo "   docker exec hypersend_mongodb mongosh -u hypersend -p Mayank@#03 --authenticationDatabase admin --eval 'db.adminCommand(\"ping\")'"
echo ""
echo "3. Check backend logs:"
echo "   docker compose logs backend"
echo ""
echo "4. Test external access from local machine:"
echo "   curl http://139.59.82.105:8000/health"
echo ""
echo "====================================================================="
