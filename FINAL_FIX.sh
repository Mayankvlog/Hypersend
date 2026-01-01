#!/bin/bash
# Final Fix - Run on VPS to deploy the corrected code

set -e

cd /hypersend/Hypersend

echo "Pulling latest code from GitHub..."
git fetch origin main
git reset --hard origin/main
echo "✓ Code pulled and verified"

echo ""
echo "Stopping containers..."
docker compose down

echo ""
echo "Removing old images..."
docker rmi hypersend-backend:latest hypersend-frontend:latest || true

echo ""
echo "Building fresh images (this will take 2-3 minutes)..."
docker compose build --no-cache

echo ""
echo "Starting containers..."
docker compose up -d

echo ""
echo "Waiting for backend to start..."
for i in {1..30}; do
    if docker compose logs backend 2>/dev/null | grep -q "Server startup complete"; then
        echo "✓ Backend started successfully!"
        break
    fi
    sleep 1
done

echo ""
docker compose ps
echo ""
echo "✓ Deployment complete!"
