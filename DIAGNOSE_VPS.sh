#!/bin/bash

# ============================================================
# VPS Diagnostic & MongoDB Fix Script
# Run this on your VPS to diagnose and fix MongoDB issues
# ============================================================

echo "====================================================================="
echo "HYPERSEND VPS DIAGNOSTIC & MONGODB FIX SCRIPT"
echo "====================================================================="
echo ""

# Check if running on VPS
if ! command -v docker &> /dev/null; then
    echo "❌ ERROR: Docker not found. Are you running this on the VPS?"
    exit 1
fi

echo "✓ Running on VPS (Docker found)"
echo ""

# ============================================================
# Step 1: Check Local MongoDB Service Status
# ============================================================
echo "---"
echo "STEP 1: Local MongoDB Service Status"
echo "---"
sudo systemctl status mongod 2>&1 | grep -E "Active:|Main PID:|exit"
echo ""

# ============================================================
# Step 2: Check Port Usage
# ============================================================
echo "---"
echo "STEP 2: Port Usage (27017)"
echo "---"
sudo lsof -i :27017 2>/dev/null || echo "✓ No process using port 27017"
echo ""

# ============================================================
# Step 3: Current Docker Status
# ============================================================
echo "---"
echo "STEP 3: Current Docker Containers"
echo "---"
docker compose ps -a
echo ""

# ============================================================
# Step 4: MongoDB Container Logs
# ============================================================
echo "---"
echo "STEP 4: MongoDB Container Logs (last 20 lines)"
echo "---"
docker compose logs mongodb --tail=20 2>/dev/null || echo "MongoDB container not running"
echo ""

# ============================================================
# Step 5: Backend Container Logs
# ============================================================
echo "---"
echo "STEP 5: Backend Container Logs (last 30 lines)"
echo "---"
docker compose logs backend --tail=30 2>/dev/null || echo "Backend container not running"
echo ""

# ============================================================
# Step 6: Network Test
# ============================================================
echo "---"
echo "STEP 6: Docker Network Test"
echo "---"
docker network ls | grep hypersend
echo ""

# ============================================================
# RECOMMENDATIONS
# ============================================================
echo "====================================================================="
echo "RECOMMENDATIONS FOR FIXING"
echo "====================================================================="
echo ""
echo "1. DISABLE LOCAL MONGODB SERVICE (to free port 27017):"
echo "   sudo systemctl stop mongod"
echo "   sudo systemctl disable mongod"
echo ""
echo "2. CLEAN UP AND RESTART DOCKER:"
echo "   docker compose down -v"
echo "   docker compose up -d --build"
echo ""
echo "3. WAIT FOR SERVICES TO BE HEALTHY:"
echo "   sleep 30"
echo "   docker compose ps"
echo ""
echo "4. TEST BACKEND CONNECTIVITY:"
echo "   curl http://localhost:8000/health"
echo ""
echo "5. TEST EXTERNAL ACCESS:"
echo "   curl http://139.59.82.105:8000/health"
echo ""
echo "====================================================================="
