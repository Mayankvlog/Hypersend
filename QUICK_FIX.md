# 🚀 QUICK FIX: Backend Connection Error

**Error:** `Firefox can't establish a connection to the server at 139.59.82.105:8000`

## Immediate Fix (Copy-Paste)

### On VPS (139.59.82.105)

```bash
# 1. SSH into VPS
ssh root@139.59.82.105

# 2. Navigate to project
cd /root/Hypersend

# 3. Check service status
docker-compose ps

# 4. Start all services
docker-compose up -d

# 5. Wait 10 seconds
sleep 10

# 6. Verify backend is running
docker-compose logs backend | tail -20

# 7. Test backend health
curl http://localhost:8000/health
```

## If Backend Still Not Responding

```bash
# Check logs for errors
docker-compose logs backend

# Restart backend specifically
docker-compose restart backend

# Wait and test again
sleep 5
curl http://localhost:8000/health

# If still failing, rebuild
docker-compose build backend
docker-compose up -d backend
```

## Verify MongoDB Connection

```bash
# Test MongoDB is running
docker-compose exec mongodb mongosh \
  -u hypersend -p 'Mayank@#03' \
  --authenticationDatabase admin \
  --eval "db.adminCommand('ping')"

# Should print: { ok: 1 }

# If MongoDB fails, restart it
docker-compose restart mongodb
docker-compose restart backend
```

## Full Health Check

```bash
# Run Python health check
python3 health_check.py

# Or manual checks:
echo "Backend:" && curl -s http://localhost:8000/health || echo "❌ Failed"
echo "Nginx:" && curl -s http://localhost:8080/health || echo "❌ Failed"
echo "MongoDB:" && docker-compose exec mongodb mongosh --eval "db.adminCommand('ping')" > /dev/null 2>&1 && echo "✅ OK" || echo "❌ Failed"
```

## Permanent Fix

Ensure Docker daemon has restart policy:

```bash
# Add to docker-compose.yml for each service:
restart: unless-stopped

# Then run:
docker-compose down
docker-compose up -d
```

## Files Added for Support

- **DEPLOY_PRODUCTION.md** - Complete deployment guide
- **TROUBLESHOOTING.md** - Detailed troubleshooting for all issues
- **deploy.sh** - Automated deployment script
- **health_check.py** - Comprehensive health monitoring
- **monitor.sh** - Auto-restart monitoring

## TL;DR - One-Liner Fix

```bash
ssh root@139.59.82.105 && cd /root/Hypersend && docker-compose restart && sleep 10 && echo "✅ Done! Access at http://139.59.82.105:8000"
```

---

**Test the fix:** Visit `http://139.59.82.105:8000/health` - you should see a green response.
