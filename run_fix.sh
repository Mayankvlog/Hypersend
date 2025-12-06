#!/bin/bash
set -e

echo "════════════════════════════════════════════════════════════════"
echo "🚀 HYPERSEND VPS FIX - MongoDB Connection & Services"
echo "════════════════════════════════════════════════════════════════"
echo ""

# Stop problematic mongod service
echo "[1/8] Stopping local mongod service..."
sudo systemctl stop mongod 2>/dev/null || true
sudo systemctl disable mongod 2>/dev/null || true

# Free port 27017
echo "[2/8] Freeing port 27017..."
sudo lsof -ti :27017 | xargs -r sudo kill -9 2>/dev/null || true

# Pull latest code
echo "[3/8] Pulling latest code..."
git pull origin main

# Verify code is correct
echo "[4/8] Verifying MongoDB configuration..."
grep -q "mongodb:27017" docker-compose.yml && echo "  ✓ docker-compose.yml OK" || exit 1
grep -q "mongodb:27017" backend/config.py && echo "  ✓ backend/config.py OK" || exit 1

# Clean Docker
echo "[5/8] Cleaning Docker resources..."
docker compose down -v 2>/dev/null || true
docker volume rm hypersend_mongodb_data hypersend_mongodb_config 2>/dev/null || true

# Rebuild and start
echo "[6/8] Building and starting services..."
docker compose build --no-cache
docker compose up -d

# Wait for initialization
echo "[7/8] Waiting for services (60 seconds)..."
sleep 60

# Verify
echo "[8/8] Verifying services..."
echo ""
docker compose ps
echo ""

if docker compose ps | grep -q "hypersend_backend.*Up.*healthy"; then
    echo "✅ SUCCESS! Backend is healthy"
    curl -s http://127.0.0.1:8000/health && echo "✅ Health check passed"
else
    echo "⚠ Services starting, may take a few more seconds"
    docker compose logs backend --tail=10
fi

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "Test in browser: http://139.59.82.105:8000"
echo "════════════════════════════════════════════════════════════════"
