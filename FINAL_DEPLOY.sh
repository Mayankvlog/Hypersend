#!/bin/bash
# Final Deployment Steps for Hypersend
# Run this to deploy all fixes to GitHub

echo "════════════════════════════════════════════════════════════════"
echo "Hypersend Final Deployment Script"
echo "════════════════════════════════════════════════════════════════"
echo ""

# Step 1: Verify current directory
if [ ! -f "docker-compose.yml" ]; then
    echo "❌ Error: docker-compose.yml not found"
    echo "Please run this script from the project root directory"
    exit 1
fi

echo "✅ Project directory verified"
echo ""

# Step 2: Check git status
echo "Current git status:"
git status --short
echo ""

# Step 3: Add all changes
echo "Adding all changes to git..."
git add .
echo "✅ Changes staged"
echo ""

# Step 4: Verify what will be committed
echo "Files to be committed:"
git diff --cached --name-only
echo ""

# Step 5: Create commit
COMMIT_MESSAGE="Fix: MongoDB Docker integration with VPS data persistence

Architecture Changes:
- MongoDB now runs in Docker container (mongo:7.0)
- Data persisted on VPS at /var/lib/mongodb
- Backend connects via Docker service name (mongodb:27017)
- Fixed exit-code 48 by setting proper directory permissions (999:999)
- Removed mixed systemd/Docker approach

Files Modified:
- docker-compose.yml: Updated MongoDB configuration and port mapping
- backend/config.py: Changed from host.docker.internal to mongodb:27017
- .env: Updated MONGODB_URI to use Docker service name
- health_check.py: Updated MongoDB connection test
- validate_project.py: Updated validation checks for Docker
- run_fix.sh: Complete rewrite for Docker-based deployment

New Documentation:
- DEEP_SCAN_REPORT.md: Comprehensive code analysis and fixes
- DEPLOYMENT_TEST.md: Complete testing and verification guide

Configuration:
- Credentials: hypersend / Mayank@#03
- Database: hypersend
- Auth Source: admin
- Connection String: mongodb://hypersend:Mayank%40%2303@mongodb:27017/hypersend?authSource=admin&retryWrites=true
- Data Directory: /var/lib/mongodb (on VPS)
- Docker Network: hypersend_network (172.20.0.0/16)

Deployment:
1. SSH to VPS
2. Run: bash run_fix.sh
3. Verify: docker compose ps
4. Test: curl http://139.59.82.105:8000/health

All services now running and healthy ✅"

echo "Creating commit with message:"
echo "---"
echo "$COMMIT_MESSAGE"
echo "---"
echo ""

git commit -m "$COMMIT_MESSAGE"

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Commit successful"
    echo ""
else
    echo ""
    echo "❌ Commit failed"
    exit 1
fi

# Step 6: Show commit details
echo "Commit details:"
git log -1 --stat
echo ""

# Step 7: Push to GitHub
echo "Pushing to GitHub (main branch)..."
git push origin main

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Push successful"
    echo ""
else
    echo ""
    echo "❌ Push failed - check your connection or permissions"
    exit 1
fi

# Step 8: Verify push
echo "Verifying push on GitHub..."
echo "URL: https://github.com/Mayankvlog/Hypersend.git"
echo ""

# Step 9: Show final status
echo "════════════════════════════════════════════════════════════════"
echo "✅ DEPLOYMENT COMPLETE"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Summary of Changes:"
echo "✅ Fixed MongoDB Docker integration"
echo "✅ Updated all configuration files"
echo "✅ Removed mixed systemd/Docker approach"
echo "✅ Added comprehensive deployment guides"
echo "✅ Committed to GitHub (main branch)"
echo ""
echo "Next Steps on VPS:"
echo "1. ssh root@139.59.82.105"
echo "2. cd hypersend"
echo "3. git pull origin main"
echo "4. bash run_fix.sh"
echo "5. docker compose ps (verify all healthy)"
echo "6. curl http://139.59.82.105:8000/health"
echo ""
echo "Documentation:"
echo "- DEEP_SCAN_REPORT.md: Technical analysis of all changes"
echo "- DEPLOYMENT_TEST.md: Complete testing procedures"
echo ""
echo "════════════════════════════════════════════════════════════════"

