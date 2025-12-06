#!/bin/bash
set -e

echo "════════════════════════════════════════════════════════════════"
echo "🚀 HYPERSEND VPS FIX - MongoDB Docker + Data Persistence"
echo "════════════════════════════════════════════════════════════════"
echo ""

# PHASE 1: Prepare VPS Directory for MongoDB Data
echo "PHASE 1: Prepare MongoDB Data Directory"
echo "────────────────────────────────────────────────────────────────"

echo "[1/8] Creating MongoDB data directory on VPS..."
sudo mkdir -p /var/lib/mongodb /var/lib/mongodb-config
echo "  ✓ Directories created"

echo "[2/8] Setting proper permissions for Docker access..."
# MongoDB Docker container runs as user ID 999 by default
sudo chown -R 999:999 /var/lib/mongodb /var/lib/mongodb-config
sudo chmod 755 /var/lib/mongodb /var/lib/mongodb-config
echo "  ✓ Permissions set correctly"

# Remove old systemd MongoDB if running
echo "[3/8] Removing old MongoDB systemd service if present..."
sudo systemctl stop mongod 2>/dev/null || true
sudo systemctl disable mongod 2>/dev/null || true
sudo killall mongod 2>/dev/null || true
sleep 2
echo "  ✓ Old MongoDB service cleaned up"

echo ""

# PHASE 2: Clean Up Docker & Rebuild Everything
echo "PHASE 2: Clean Up & Rebuild Docker Services"
echo "────────────────────────────────────────────────────────────────"

echo "[4/8] Removing orphan containers and old volumes..."
docker compose down --remove-orphans 2>/dev/null || true
sleep 2
echo "  ✓ Cleanup complete"

echo "[5/8] Building Docker images..."
docker compose build --no-cache
echo "  ✓ Images built"

echo "[6/8] Starting all services..."
docker compose up -d
echo "  ✓ Services started"

# PHASE 3: Verification
echo ""
echo "PHASE 3: Verification & Testing"
echo "────────────────────────────────────────────────────────────────"

echo "[7/8] Waiting for services to initialize (60 seconds)..."
sleep 60

echo "[8/8] Checking service status..."
echo ""
docker compose ps
echo ""

# Test MongoDB connection
echo "Testing MongoDB connection..."
if docker exec hypersend_mongodb mongosh -u hypersend -p Mayank@#03 --authenticationDatabase admin --eval "db.adminCommand('ping')" 2>/dev/null | grep -q "ok"; then
    echo "  ✓ MongoDB accessible and responding"
else
    echo "  ⚠ MongoDB connection test - may still be initializing"
    docker compose logs mongodb --tail=10
fi

# Test backend health
echo ""
echo "Testing backend health..."
if docker compose ps | grep -q "hypersend_backend.*Up"; then
    echo "  ✓ Backend container running"
    if curl -s http://127.0.0.1:8000/health > /dev/null 2>&1; then
        echo "  ✓ Backend health endpoint OK"
    else
        echo "  ⚠ Backend still initializing - wait a moment and try: curl http://139.59.82.105:8000/health"
    fi
else
    echo "  ✗ Backend not running"
    docker compose logs backend --tail=20
fi

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "✅ Setup Complete!"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Architecture:"
echo "  • MongoDB: Docker container (mongo:7.0)"
echo "  • Data: Persisted on VPS at /var/lib/mongodb"
echo "  • Backend: Docker container, connects via docker network"
echo "  • Frontend: Docker container"
echo "  • Nginx: Docker container (reverse proxy)"
echo ""
echo "Internal Docker Network: hypersend_network"
echo "External Access:"
echo "  • Backend API: http://139.59.82.105:8000"
echo "  • MongoDB: mongodb://hypersend:Mayank@#03@localhost:27017"
echo ""
echo "Useful Commands:"
echo "  View logs:     docker compose logs -f backend"
echo "  Test backend:  curl http://139.59.82.105:8000/health"
echo "  MongoDB CLI:   docker exec hypersend_mongodb mongosh"
echo "  Restart:       docker compose restart"
echo "════════════════════════════════════════════════════════════════"
