# 🔧 Troubleshooting Guide - Hypersend

## Common Issues & Solutions

### 1. Backend Connection Error (Unable to connect to 139.59.82.105:8000)

**Error Message:**
```
Firefox can't establish a connection to the server at 139.59.82.105:8000.
```

**Cause:** The backend Docker container is not running on the VPS.

**Solution:**

#### Option A: SSH to VPS and Start Services
```bash
# 1. Connect to VPS
ssh root@139.59.82.105

# 2. Navigate to project
cd /root/Hypersend

# 3. Check service status
docker-compose ps

# 4. If services are stopped, start them
docker-compose up -d

# 5. Check backend is running
docker-compose logs backend --tail=20
```

#### Option B: Quick Fix (Local Docker)
```bash
# From your local machine in project directory
cd c:\Users\mayan\Downloads\Addidas\hypersend

# Ensure .env has correct MongoDB URI
cat .env | grep MONGODB_URI
# Should show: MONGODB_URI=mongodb://hypersend:Mayank%40%2303@139.59.82.105:27017/hypersend?authSource=admin

# Start services
docker-compose up -d

# Wait 10 seconds for startup
sleep 10

# Check backend health
curl http://localhost:8000/health
```

### 2. Backend Logs Show "Unable to connect to MongoDB"

**Error Message:**
```
pymongo.errors.ServerSelectionTimeoutError: no servers match selector
```

**Cause:** MongoDB on VPS is not accessible or credentials are wrong.

**Solution:**

```bash
# 1. SSH to VPS
ssh root@139.59.82.105

# 2. Check if MongoDB is running
docker-compose ps mongodb

# 3. Check MongoDB logs
docker-compose logs mongodb --tail=50

# 4. Test MongoDB connection
docker-compose exec mongodb mongosh \
  -u hypersend -p 'Mayank@#03' \
  --authenticationDatabase admin \
  --eval "db.adminCommand('ping')"

# 5. If MongoDB isn't responding, restart it
docker-compose restart mongodb

# 6. Restart backend after MongoDB is ready
sleep 10
docker-compose restart backend
```

### 3. Nginx Returns "Bad Gateway" (502)

**Error Message:**
```
502 Bad Gateway
```

**Cause:** Nginx can't reach the backend service.

**Solution:**

```bash
# 1. Check if backend is running
docker-compose ps backend

# 2. Check backend logs
docker-compose logs backend --tail=50

# 3. Test backend directly
docker-compose exec backend curl http://localhost:8000/health

# 4. If not responding, restart backend
docker-compose restart backend

# 5. Check nginx configuration
docker-compose exec nginx nginx -t

# 6. Restart nginx if config is OK
docker-compose restart nginx
```

### 4. Port Already in Use

**Error Message:**
```
bind: address already in use
```

**Cause:** Another service is using ports 8000, 8080, or 27017.

**Solution:**

```bash
# Find which process is using the port
lsof -i :8000    # Backend
lsof -i :8080    # Nginx
lsof -i :27017   # MongoDB

# Kill the process
kill -9 <PID>

# Or change ports in docker-compose.yml
# Example: Change 8000:8000 to 8001:8000
```

### 5. Frontend Can't Connect to Backend API

**Error Message (in frontend logs):**
```
Connection refused: [Errno 61] Connection refused
```

**Cause:** Frontend is using wrong API URL.

**Solution:**

```bash
# 1. Check frontend environment
cat frontend/.env.production

# Should contain:
# FRONTEND_API_URL=http://139.59.82.105:8000

# 2. Update if needed
echo "FRONTEND_API_URL=http://139.59.82.105:8000" > frontend/.env.production

# 3. Rebuild frontend
docker-compose build frontend

# 4. Restart frontend
docker-compose up -d frontend
```

### 6. MongoDB Authentication Failed

**Error Message:**
```
Unauthorized: authentication failed
```

**Cause:** Wrong MongoDB credentials.

**Solution:**

```bash
# 1. Check .env file credentials
grep MONGO .env
# Should show: MONGO_USER=hypersend, MONGO_PASSWORD=Mayank@#03

# 2. Connect with correct credentials
docker-compose exec mongodb mongosh \
  -u hypersend -p 'Mayank@#03' \
  --authenticationDatabase admin \
  hypersend

# 3. If still failing, reinitialize MongoDB
docker-compose down mongodb
docker volume rm hypersend_mongodb_data hypersend_mongodb_config
docker-compose up -d mongodb
docker-compose restart backend
```

### 7. Services Keep Crashing/Restarting

**Cause:** Dependency issues or insufficient resources.

**Solution:**

```bash
# 1. Check docker logs
docker-compose logs

# 2. Check disk space
df -h

# 3. Check memory usage
docker stats

# 4. Rebuild images
docker-compose build --no-cache

# 5. Start fresh
docker-compose down
docker-compose up -d

# 6. Monitor logs
docker-compose logs -f
```

### 8. File Upload/Download Not Working

**Error Message:**
```
500 Internal Server Error
413 Payload Too Large
```

**Cause:** File size limit or upload path permissions.

**Solution:**

```bash
# 1. Check nginx upload size limit
grep client_max_body_size nginx.conf

# 2. Should be at least 40GB (42949672960 bytes)
# If not, update nginx.conf:
# client_max_body_size 40G;

# 3. Rebuild nginx
docker-compose build nginx

# 4. Check file permissions
docker-compose exec backend ls -la /data/
docker-compose exec backend ls -la /app/uploads/

# 5. If permissions are wrong, fix them
docker-compose exec backend chmod -R 777 /data
docker-compose exec backend chmod -R 777 /app/uploads

# 6. Restart services
docker-compose restart nginx backend
```

## Health Check

Run the comprehensive health check script:

```bash
# On VPS
cd /root/Hypersend
python3 health_check.py

# Expected output:
# ✅ Docker Services Status - All running
# ✅ Backend API Health - OK
# ✅ Nginx Reverse Proxy Health - OK
# ✅ MongoDB Connection - OK
# ✅ All services operational!
```

## Monitoring

### View Live Logs
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f backend
docker-compose logs -f mongodb
docker-compose logs -f nginx
docker-compose logs -f frontend
```

### Check Service Status
```bash
# Detailed status
docker-compose ps

# Pretty format
docker-compose ps --format table
```

### Test Connectivity
```bash
# Test backend
curl http://139.59.82.105:8000/health

# Test nginx
curl http://139.59.82.105:8080/health

# Test API endpoint
curl http://139.59.82.105:8000/api/auth/status
```

## Emergency Recovery

If all services are down:

```bash
# 1. Stop everything
docker-compose down

# 2. Clean up volumes (WARNING: Deletes data!)
docker volume rm $(docker volume ls -q | grep hypersend)

# 3. Pull fresh images
docker-compose pull

# 4. Start with fresh environment
docker-compose up -d

# 5. Check status
docker-compose ps

# 6. Monitor startup
docker-compose logs -f
```

## Performance Optimization

### Increase Resources (VPS)
```bash
# Add memory limit
docker update --memory 2g hypersend_backend
docker update --memory 4g hypersend_mongodb

# Restart services
docker-compose restart
```

### Enable Caching
```bash
# Update nginx.conf
# Add cache headers
add_header Cache-Control "public, max-age=3600";

# Rebuild nginx
docker-compose build nginx
docker-compose restart nginx
```

### Database Optimization
```bash
# Connect to MongoDB
docker-compose exec mongodb mongosh -u hypersend -p 'Mayank@#03' hypersend

# Check database stats
db.stats()

# Optimize collections
db.users.reIndex()
db.chats.reIndex()
db.messages.reIndex()
```

## Support Checklist

When reporting issues, include:

- [ ] Docker version: `docker --version`
- [ ] Docker Compose version: `docker-compose --version`
- [ ] Service logs: `docker-compose logs > logs.txt`
- [ ] Status output: `docker-compose ps`
- [ ] Disk space: `df -h`
- [ ] Memory usage: `docker stats --no-stream`
- [ ] Network connectivity: `ping 139.59.82.105`
- [ ] Port availability: `lsof -i :8000`

## Quick Restart

```bash
#!/bin/bash
# Copy and save as restart.sh, then run: bash restart.sh

cd /root/Hypersend
echo "Stopping services..."
docker-compose down
echo "Starting services..."
docker-compose up -d
echo "Waiting for startup..."
sleep 10
echo "Checking status..."
docker-compose ps
echo "Health check..."
curl -s http://localhost:8080/health && echo "✅ Nginx OK" || echo "❌ Nginx Failed"
curl -s http://localhost:8000/health && echo "✅ Backend OK" || echo "❌ Backend Failed"
```

---

**Need more help?**
- Check logs: `docker-compose logs`
- Test connectivity: `curl http://139.59.82.105:8000/health`
- SSH to VPS: `ssh root@139.59.82.105`
- View documentation: `cat DEPLOY_PRODUCTION.md`
