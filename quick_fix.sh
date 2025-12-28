#!/bin/bash
# QUICK FIX - Run this on the VPS to resolve all deployment issues

echo "🔧 Running deployment fixes..."

cd /root/hypersend

# Fix 1: Remove docker-compose version attribute
echo "1. Removing obsolete version attribute from docker-compose.yml..."
sed -i '/^version:/d' docker-compose.yml
sed -i '/^#version:/d' docker-compose.yml

# Fix 2: Configure git
echo "2. Configuring git for branch divergence..."
git config pull.rebase true

# Fix 3: Restart services
echo "3. Restarting Docker services..."
docker compose down
sleep 2

# Fix 4: Rebuild and start
echo "4. Building and starting services..."
docker compose build --no-cache backend frontend
docker compose up -d

# Fix 5: Wait for health
echo "5. Waiting for services to be healthy..."
sleep 30

# Fix 6: Verify
echo "6. Verifying deployment..."
docker compose ps

echo ""
echo "✅ Deployment fixed!"
echo ""
echo "Test with:"
echo "  curl -i https://zaply.in.net/health"
echo "  curl -i https://zaply.in.net/api/v1/health"
