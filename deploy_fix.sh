#!/bin/bash
# Quick Deployment Fix for VPS - Execute on: root@hypersend:~/hypersend

set -e  # Exit on any error

echo "🔧 Hypersend Deployment Fix Script"
echo "===================================="
echo ""

# Fix 1: Remove obsolete version attribute
echo "📝 Step 1: Fixing docker-compose.yml..."
if grep -q "^version:" docker-compose.yml; then
    sed -i '/^version:/d' docker-compose.yml
    echo "✅ Removed version: attribute"
fi

# Fix 2: Configure git for rebase
echo "📝 Step 2: Configuring git..."
git config pull.rebase true
echo "✅ Git configured for rebase"

# Fix 3: Stop old containers
echo "📝 Step 3: Stopping old containers..."
docker compose down --remove-orphans 2>/dev/null || true
echo "✅ Containers stopped"

# Fix 4: Rebuild without cache
echo "📝 Step 4: Rebuilding Docker images (this may take 2-3 minutes)..."
docker compose build --no-cache backend frontend
echo "✅ Images rebuilt"

# Fix 5: Start services
echo "📝 Step 5: Starting services..."
docker compose up -d
echo "✅ Services started"

# Fix 6: Wait for services
echo "⏳ Waiting 30 seconds for services to be fully healthy..."
sleep 30

# Fix 7: Verify status
echo "📝 Step 6: Verifying deployment..."
docker compose ps

echo ""
echo "📊 Container Status Check"
echo "=========================="
echo ""

# Check backend health
echo -n "Backend health: "
if docker compose exec -T backend curl -s http://localhost:8000/health | grep -q "healthy"; then
    echo "✅ Healthy"
else
    echo "⚠️  Check logs with: docker compose logs backend"
fi

# Check if nginx is up
echo -n "Nginx status: "
if docker compose ps nginx | grep -q "Up"; then
    echo "✅ Running"
else
    echo "⚠️  Check logs with: docker compose logs nginx"
fi

# Check MongoDB
echo -n "MongoDB status: "
if docker compose ps mongodb | grep -q "Up"; then
    echo "✅ Running"
else
    echo "⚠️  Check logs with: docker compose logs mongodb"
fi

echo ""
echo "🧪 Next: Test CORS from browser at https://zaply.in.net"
echo "   Expected: No 'Cannot connect to server' error"
echo ""
echo "✅ Deployment fixes complete!"
echo ""
