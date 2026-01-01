#!/bin/bash
# VPS Deployment Script - Clean Build & Deploy

set -e  # Exit on any error

echo "=========================================="
echo "Hypersend Backend - Clean Deployment"
echo "=========================================="
echo ""

cd /hypersend/Hypersend

echo "[1/6] Pulling latest code from git..."
git fetch origin main
git reset --hard origin/main
git clean -fd
echo "✓ Code updated"
echo ""

echo "[2/6] Stopping all containers..."
docker compose down -v --remove-orphans
echo "✓ Containers stopped"
echo ""

echo "[3/6] Removing old Docker images..."
docker rmi hypersend-backend:latest || true
docker rmi hypersend-frontend:latest || true
echo "✓ Old images removed"
echo ""

echo "[4/6] Building fresh Docker images..."
docker compose build --no-cache
echo "✓ Docker images built"
echo ""

echo "[5/6] Starting containers..."
docker compose up -d
echo "✓ Containers started"
echo ""

echo "[6/6] Waiting for backend to be healthy..."
sleep 5

HEALTHY=false
for i in {1..30}; do
    if docker compose ps backend | grep -q "healthy"; then
        HEALTHY=true
        break
    fi
    echo "Attempt $i/30: Backend starting..."
    sleep 1
done

if [ "$HEALTHY" = true ]; then
    echo "✓ Backend is healthy!"
    echo ""
    echo "=========================================="
    echo "Deployment Complete!"
    echo "=========================================="
    docker compose ps
    echo ""
    echo "Testing health endpoint..."
    sleep 2
    curl -s https://zaply.in.net/api/v1/health | jq . || echo "Health check endpoint test (may fail if no HTTPS cert yet)"
else
    echo "✗ Backend failed to become healthy"
    echo ""
    echo "Backend logs:"
    docker compose logs backend --tail=50
    exit 1
fi
