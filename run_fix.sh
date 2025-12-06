#!/bin/bash
set -e

echo "════════════════════════════════════════════════════════════════"
echo "🚀 HYPERSEND VPS FIX - MongoDB Local Service + Docker"
echo "════════════════════════════════════════════════════════════════"
echo ""

# PHASE 1: Setup Local MongoDB Service
echo "PHASE 1: Setup Local MongoDB Service on VPS"
echo "────────────────────────────────────────────────────────────────"

# Check if MongoDB is installed
if ! command -v mongod &> /dev/null; then
    echo "[1/9] Installing MongoDB..."
    sudo apt-get update -qq
    sudo apt-get install -y mongodb-org 2>/dev/null || sudo apt-get install -y mongodb 2>/dev/null
    echo "  ✓ MongoDB installed"
else
    echo "[1/9] MongoDB already installed"
fi

# Stop and clean old mongod
echo "[2/9] Cleaning up old MongoDB processes..."
sudo systemctl stop mongod 2>/dev/null || true
sudo killall mongod 2>/dev/null || true
sleep 2

# Restart mongod service
echo "[3/9] Starting MongoDB service..."
sudo systemctl start mongod
sudo systemctl enable mongod
sleep 3

# Verify MongoDB is running
echo "[4/9] Verifying MongoDB is running..."
if pgrep -x "mongod" > /dev/null; then
    echo "  ✓ MongoDB service running"
else
    echo "  ✗ MongoDB failed to start!"
    exit 1
fi

# Initialize MongoDB with auth (if not already done)
echo "[5/9] Initializing MongoDB credentials..."
mongosh --eval "
var adminUser = db.getCollection('system.version').findOne();
if (!adminUser) {
    use admin;
    db.createUser({
        user: 'hypersend',
        pwd: 'Mayank@#03',
        roles: ['root']
    });
    print('MongoDB user created');
} else {
    print('MongoDB user already exists');
}
" 2>/dev/null || echo "  ℹ MongoDB auth may already be set"

echo ""

# PHASE 2: Update & Rebuild Docker Services
echo "PHASE 2: Update & Rebuild Docker Services"
echo "────────────────────────────────────────────────────────────────"

echo "[6/9] Pulling latest code..."
git pull origin main

echo "[7/9] Building and starting Docker services..."
docker compose down 2>/dev/null || true
docker compose build --no-cache
docker compose up -d

# PHASE 3: Verification
echo "[8/9] Waiting for services to start (30 seconds)..."
sleep 30

echo "[9/9] Verifying services..."
echo ""
docker compose ps
echo ""

# Test MongoDB connection from backend
echo "Testing MongoDB connection..."
if mongosh -u hypersend -p Mayank@#03 --authenticationDatabase admin --eval "db.adminCommand('ping')" 2>/dev/null | grep -q "ok"; then
    echo "  ✓ MongoDB accessible"
else
    echo "  ⚠ MongoDB connection check"
fi

# Test backend health
echo "Testing backend health..."
if docker compose ps | grep -q "hypersend_backend.*Up"; then
    echo "  ✓ Backend container running"
    curl -s http://127.0.0.1:8000/health && echo "  ✓ Backend health OK" || echo "  ⚠ Backend still initializing"
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
echo "  • MongoDB: Runs on VPS as local service (localhost:27017)"
echo "  • Backend: Docker container connects via host.docker.internal"
echo "  • Frontend: Docker container"
echo "  • Nginx: Docker container"
echo ""
echo "Test in browser: http://139.59.82.105:8000"
echo "════════════════════════════════════════════════════════════════"
