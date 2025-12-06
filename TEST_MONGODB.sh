#!/bin/bash

# ============================================================
# MongoDB Connection Tester
# Tests if backend can connect to MongoDB through Docker
# Run this after docker compose up -d --build
# ============================================================

echo "====================================================================="
echo "MONGODB CONNECTION VERIFICATION"
echo "====================================================================="
echo ""

# Check if containers are running
echo "[1/5] Checking if MongoDB container is running..."
if docker compose ps mongodb | grep -q "Up"; then
    echo "✓ MongoDB container is running"
else
    echo "❌ MongoDB container is NOT running"
    echo "   Run: docker compose up -d --build"
    exit 1
fi
echo ""

# Test MongoDB with mongosh directly
echo "[2/5] Testing MongoDB connection with mongosh..."
if docker compose exec -T mongodb mongosh -u hypersend -p Mayank@#03 --authenticationDatabase admin --eval "db.adminCommand('ping')" 2>/dev/null | grep -q '"ok": 1'; then
    echo "✓ MongoDB is responding to ping"
else
    echo "⚠ MongoDB ping response unclear, checking logs..."
    docker compose logs mongodb | tail -5
fi
echo ""

# Check if backend container is running
echo "[3/5] Checking if backend container is running..."
if docker compose ps backend | grep -q "Up"; then
    echo "✓ Backend container is running"
else
    echo "❌ Backend container is NOT running"
    echo "   Logs:"
    docker compose logs backend --tail=10
    exit 1
fi
echo ""

# Test backend health check
echo "[4/5] Testing backend health check..."
if curl -s http://127.0.0.1:8000/health | grep -q "status"; then
    echo "✓ Backend health check responding"
    echo "   Response: $(curl -s http://127.0.0.1:8000/health)"
else
    echo "⚠ Backend health check not responding yet"
    echo "   Backend logs:"
    docker compose logs backend --tail=15
fi
echo ""

# Check MongoDB connection from backend logs
echo "[5/5] Checking backend MongoDB connection logs..."
if docker compose logs backend | grep -qi "mongodb\|connected\|connection"; then
    echo "✓ Backend has MongoDB connection logs"
    echo "   Last 5 related lines:"
    docker compose logs backend | grep -i "mongodb\|connected" | tail -5
else
    echo "⚠ No MongoDB connection messages found yet (services may still be initializing)"
fi
echo ""

echo "====================================================================="
echo "SUMMARY"
echo "====================================================================="
echo ""

# Get service status
echo "Service Status:"
docker compose ps
echo ""

# Network test
echo "Docker Network:"
docker network inspect hypersend_network 2>/dev/null | grep -A 20 "Containers" || echo "Network info not available"
echo ""

echo "====================================================================="
echo "NEXT STEPS:"
echo "====================================================================="
echo "1. If services are healthy, test external access:"
echo "   curl http://139.59.82.105:8000/health"
echo ""
echo "2. If still having issues, check:"
echo "   docker compose logs backend"
echo "   docker compose logs mongodb"
echo ""
echo "3. If needed, run full diagnostic:"
echo "   bash DIAGNOSE_VPS.sh"
echo ""
echo "====================================================================="
