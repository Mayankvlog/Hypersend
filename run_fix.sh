#!/bin/bash
set -e

echo "════════════════════════════════════════════════════════════════"
echo "🚀 HYPERSEND VPS FIX - MongoDB Connection & Services"
echo "════════════════════════════════════════════════════════════════"
echo ""

# Stop problematic mongod service
echo "[1/9] Stopping local mongod service..."
sudo systemctl stop mongod 2>/dev/null || true
sudo systemctl disable mongod 2>/dev/null || true

# Free port 27017
echo "[2/9] Freeing port 27017..."
sudo lsof -ti :27017 | xargs -r sudo kill -9 2>/dev/null || true

# Pull latest code
echo "[3/9] Pulling latest code..."
git pull origin main

# Verify code is correct
echo "[4/9] Verifying MongoDB configuration..."
grep -q "mongodb:27017" docker-compose.yml && echo "  ✓ docker-compose.yml OK" || exit 1
grep -q "mongodb:27017" backend/config.py && echo "  ✓ backend/config.py OK" || exit 1

# Clean Docker (IMPORTANT: Must remove volumes to reset MongoDB)
echo "[5/9] Cleaning Docker resources..."
docker compose down -v 2>/dev/null || true
docker volume rm hypersend_mongodb_data hypersend_mongodb_config 2>/dev/null || true
docker system prune -f 2>/dev/null || true

# Rebuild and start (volumes deleted = fresh MongoDB initialization)
echo "[6/9] Building and starting services..."
docker compose build --no-cache
docker compose up -d

# Wait for MongoDB to initialize with credentials
echo "[7/9] Waiting for services (90 seconds for MongoDB auth setup)..."
sleep 90

# Verify
echo "[8/9] Verifying services..."
echo ""
docker compose ps
echo ""

# Check MongoDB
echo "Checking MongoDB..."
if docker compose exec -T mongodb mongosh -u hypersend -p Mayank@#03 --authenticationDatabase admin --eval "db.adminCommand('ping')" 2>/dev/null | grep -q "ok"; then
    echo "  ✓ MongoDB authentication OK"
else
    echo "  ⚠ MongoDB auth check"
fi

# Check backend
echo "Checking backend..."
if docker compose ps | grep -q "hypersend_backend.*Up.*healthy"; then
    echo "✅ SUCCESS! Backend is healthy"
    curl -s http://127.0.0.1:8000/health && echo "✅ Health check passed"
else
    echo "⚠ Backend logs:"
    docker compose logs backend --tail=15
fi

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "Test in browser: http://139.59.82.105:8000"
echo "════════════════════════════════════════════════════════════════"
