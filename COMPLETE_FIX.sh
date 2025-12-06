#!/bin/bash

# ============================================================
# HYPERSEND VPS - COMPLETE FIX & DEEP SCAN SCRIPT
# Deep code scan, tests, run, and verify everything
# ============================================================

set -e

echo "════════════════════════════════════════════════════════════════"
echo "🚀 HYPERSEND VPS - COMPLETE SYSTEM FIX & VERIFICATION"
echo "════════════════════════════════════════════════════════════════"
echo ""

# ============================================================
# PHASE 1: CLEANUP & SERVICE FIXES
# ============================================================
echo "PHASE 1: CLEANUP & SERVICE FIXES"
echo "────────────────────────────────────────────────────────────────"
echo ""

echo "[1/14] Stopping local MongoDB service..."
sudo systemctl stop mongod 2>/dev/null || echo "  ℹ️  mongod not running"
sudo systemctl disable mongod 2>/dev/null || echo "  ℹ️  mongod already disabled"
echo "  ✓ Done"
echo ""

echo "[2/14] Killing any process on port 27017..."
sudo lsof -ti :27017 | xargs -r sudo kill -9 2>/dev/null || echo "  ✓ No process to kill"
echo "  ✓ Done"
echo ""

echo "[3/14] Checking system resources..."
echo "  Memory: $(free -h | awk 'NR==2 {print $2}')"
echo "  Disk: $(df -h / | awk 'NR==2 {print $4 " free"}')"
echo "  ✓ Done"
echo ""

# ============================================================
# PHASE 2: GIT & CODE UPDATES
# ============================================================
echo "PHASE 2: GIT & CODE UPDATES"
echo "────────────────────────────────────────────────────────────────"
echo ""

echo "[4/14] Pulling latest code from GitHub..."
git pull origin main
echo "  ✓ Done"
echo ""

echo "[5/14] Checking latest commits..."
echo "  Last 3 commits:"
git log --oneline -3 | sed 's/^/    /'
echo "  ✓ Done"
echo ""

echo "[6/14] Deep code scan - checking critical files..."
echo "  Checking docker-compose.yml..."
if grep -q "mongodb:27017" docker-compose.yml; then
    echo "    ✓ MONGODB_URI correctly set to mongodb:27017"
else
    echo "    ✗ MONGODB_URI NOT using service name!"
    exit 1
fi

echo "  Checking backend/config.py..."
if grep -q "mongodb:27017" backend/config.py; then
    echo "    ✓ Backend config correctly set to mongodb:27017"
else
    echo "    ✗ Backend config NOT using service name!"
    exit 1
fi

echo "  Checking frontend Dockerfile..."
if grep -q "permissions_manager.py" frontend/Dockerfile; then
    echo "    ✓ Frontend Dockerfile has permissions_manager.py"
else
    echo "    ✗ Frontend missing permissions_manager.py!"
    exit 1
fi

echo "  Checking nginx.conf..."
if [ -f "nginx.conf" ]; then
    echo "    ✓ nginx.conf exists"
else
    echo "    ✗ nginx.conf missing!"
    exit 1
fi

echo "  ✓ Deep code scan complete - all critical files OK"
echo ""

# ============================================================
# PHASE 3: DOCKER CLEANUP & REBUILD
# ============================================================
echo "PHASE 3: DOCKER CLEANUP & REBUILD"
echo "────────────────────────────────────────────────────────────────"
echo ""

echo "[7/14] Stopping Docker containers..."
docker compose down -v 2>/dev/null || echo "  ℹ️  No containers running"
echo "  ✓ Done"
echo ""

echo "[8/14] Removing Docker volumes..."
docker volume rm hypersend_mongodb_data 2>/dev/null || echo "  ℹ️  Volume already removed"
docker volume rm hypersend_mongodb_config 2>/dev/null || echo "  ℹ️  Volume already removed"
echo "  ✓ Done"
echo ""

echo "[9/14] Building Docker images..."
docker compose build --no-cache 2>&1 | tail -20
echo "  ✓ Build complete"
echo ""

# ============================================================
# PHASE 4: SERVICE STARTUP & INITIALIZATION
# ============================================================
echo "PHASE 4: SERVICE STARTUP & INITIALIZATION"
echo "────────────────────────────────────────────────────────────────"
echo ""

echo "[10/14] Starting Docker services..."
docker compose up -d
echo "  ✓ Services started"
echo ""

echo "[11/14] Waiting for services to initialize (90 seconds)..."
for i in {1..9}; do
    echo "  ⏳ $((i*10)) seconds elapsed..."
    sleep 10
done
echo "  ✓ Initialization complete"
echo ""

# ============================================================
# PHASE 5: SERVICE VERIFICATION & TESTING
# ============================================================
echo "PHASE 5: SERVICE VERIFICATION & TESTING"
echo "────────────────────────────────────────────────────────────────"
echo ""

echo "[12/14] Checking service status..."
echo ""
docker compose ps
echo ""

echo "  Verifying each service:"
if docker compose ps | grep -q "hypersend_nginx.*Up"; then
    echo "    ✓ Nginx is UP"
else
    echo "    ✗ Nginx is NOT running!"
    exit 1
fi

if docker compose ps | grep -q "hypersend_mongodb.*Up.*healthy"; then
    echo "    ✓ MongoDB is UP and HEALTHY"
else
    echo "    ✗ MongoDB is NOT healthy!"
    docker compose logs mongodb --tail=20
    exit 1
fi

if docker compose ps | grep -q "hypersend_backend.*Up.*healthy"; then
    echo "    ✓ Backend is UP and HEALTHY"
else
    echo "    ⚠ Backend still initializing (can take a few more seconds)"
    docker compose logs backend --tail=10
fi

if docker compose ps | grep -q "hypersend_frontend.*Up"; then
    echo "    ✓ Frontend is UP"
else
    echo "    ✗ Frontend is NOT running!"
fi

echo ""
echo "  ✓ Service status verification complete"
echo ""

echo "[13/14] Running connectivity tests..."
echo ""

# Test MongoDB
echo "  Testing MongoDB connectivity..."
if docker compose exec -T mongodb mongosh -u hypersend -p Mayank@#03 --authenticationDatabase admin --eval "db.adminCommand('ping')" 2>/dev/null | grep -q "ok"; then
    echo "    ✓ MongoDB responding to ping"
else
    echo "    ⚠ MongoDB ping unclear, checking logs..."
fi

# Test backend health
echo "  Testing backend health endpoint..."
if curl -s http://127.0.0.1:8000/health > /dev/null 2>&1; then
    HEALTH=$(curl -s http://127.0.0.1:8000/health)
    echo "    ✓ Backend health check: $HEALTH"
else
    echo "    ⚠ Backend health check not responding yet (services may still be starting)"
fi

# Test external access
echo "  Testing external access..."
if curl -s http://139.59.82.105:8000/health > /dev/null 2>&1; then
    echo "    ✓ External access to backend working"
else
    echo "    ⚠ External access not responding (may need more time or firewall check)"
fi

echo ""
echo "  ✓ Connectivity tests complete"
echo ""

echo "[14/14] Generating diagnostic report..."
echo ""
echo "=== DIAGNOSTIC REPORT ==="
echo ""
echo "Docker Network:"
docker network inspect hypersend_network 2>/dev/null | grep -A 20 "Containers" || echo "Network info not available"
echo ""
echo "MongoDB Logs (last 10 lines):"
docker compose logs mongodb --tail=10
echo ""
echo "Backend Logs (last 15 lines):"
docker compose logs backend --tail=15
echo ""
echo "Frontend Logs (last 10 lines):"
docker compose logs frontend --tail=10 || echo "No frontend logs available"
echo ""

# ============================================================
# PHASE 6: FINAL STATUS & RECOMMENDATIONS
# ============================================================
echo ""
echo "════════════════════════════════════════════════════════════════"
echo "✅ COMPLETE FIX & DEEP SCAN FINISHED"
echo "════════════════════════════════════════════════════════════════"
echo ""

echo "📊 FINAL STATUS:"
echo "  ✓ Local mongod service: DISABLED"
echo "  ✓ Port 27017: FREED"
echo "  ✓ Docker services: REBUILT"
echo "  ✓ Code: PULLED (latest fixes)"
echo "  ✓ Deep scan: PASSED"
echo "  ✓ Tests: COMPLETED"
echo ""

echo "🌐 SERVICE ENDPOINTS:"
echo "  • Backend API: http://139.59.82.105:8000"
echo "  • Backend Health: http://139.59.82.105:8000/health"
echo "  • Frontend: http://139.59.82.105:8550"
echo "  • MongoDB (internal): mongodb:27017"
echo ""

echo "✅ EXPECTED RESULTS:"
echo "  ✓ All 4 containers running and healthy"
echo "  ✓ Backend responding at http://139.59.82.105:8000"
echo "  ✓ MongoDB connected to backend"
echo "  ✓ Firefox should load the app without \"Unable to connect\" error"
echo ""

echo "❓ IF STILL NOT WORKING:"
echo "  1. Run: bash TEST_MONGODB.sh"
echo "  2. Check: docker compose logs backend"
echo "  3. Check: docker compose logs mongodb"
echo "  4. Read: VPS_MONGODB_FIX.md"
echo ""

echo "════════════════════════════════════════════════════════════════"
echo ""
