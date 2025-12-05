# Docker Compose Port 80 Conflict - Troubleshooting Guide

## Problem
```
Error: failed to bind host port 0.0.0.0:80/tcp: address already in use
```

This error occurs when another process or Docker container is already using port 80.

---

## Quick Fix

### Option 1: Run Auto-Fix Script (Recommended)

**Linux/macOS:**
```bash
chmod +x fix_port_conflict.sh
./fix_port_conflict.sh
```

**Windows:**
```cmd
fix_port_conflict.bat
```

---

## Manual Solutions

### Linux/macOS

#### Check what's using port 80:
```bash
lsof -i :80
# or
netstat -tlnp | grep :80
# or
sudo ss -tlnp | grep :80
```

#### Kill the process:
```bash
# Option 1: Using fuser
sudo fuser -k 80/tcp

# Option 2: Using kill
sudo kill -9 <PID>
```

#### Alternative: Change Port (if can't free port 80)
Edit `docker-compose.yml`:
```yaml
nginx:
  ports:
    - "8080:80"  # Use 8080 instead of 80
    - "443:443"
```

### Windows

#### Check what's using port 80:
```cmd
netstat -ano | findstr ":80"
```

This shows output like:
```
TCP    0.0.0.0:80    0.0.0.0:0    LISTENING    4532
```

The PID is `4532` in this example.

#### Kill the process:
```cmd
# Option 1: Using taskkill
taskkill /PID 4532 /F

# Option 2: Using Task Manager
# 1. Press Ctrl+Shift+Esc
# 2. Find the process with the PID
# 3. Right-click and select "End Task"
```

#### Alternative: Change Port (if can't free port 80)
Edit `docker-compose.yml`:
```yaml
nginx:
  ports:
    - "8080:80"  # Use 8080 instead of 80
    - "443:443"
```

---

## Common Processes Using Port 80

| Process | Platform | Solution |
|---------|----------|----------|
| Apache | Linux | `sudo systemctl stop apache2` |
| Nginx | Linux | `sudo systemctl stop nginx` |
| IIS | Windows | Stop in Services.msc |
| Skype | Windows/Mac | Close Skype app |
| HTTP Server | Any | Kill process by PID |
| Other Docker | Any | Run `docker compose down` first |

---

## Complete Docker Reset

If nothing works, do a complete reset:

```bash
# Stop all containers
docker compose down -v

# Clean up Docker system (careful - removes unused containers/images)
docker system prune -a --volumes

# Then start fresh
docker compose pull
docker compose up -d --build
```

---

## Verify Fix

After running the fix:

```bash
# Check if containers are running
docker compose ps

# Should show:
# - hypersend_nginx         Running
# - hypersend_backend       Running
# - hypersend_frontend      Running
# - hypersend_mongodb       Running

# Check if port 80 is working
curl http://localhost

# Or check logs
docker compose logs nginx
```

---

## Access Application

Once fixed, access your application:

- **Frontend:** http://localhost
- **API Docs:** http://localhost/api/v1/docs
- **API Base:** http://localhost/api/v1

---

## Docker Compose Health Check

Monitor container health:

```bash
# Real-time logs
docker compose logs -f

# Specific service logs
docker compose logs -f nginx
docker compose logs -f backend
docker compose logs -f mongodb
docker compose logs -f frontend

# Container stats
docker compose stats
```

---

## Advanced Troubleshooting

### If Nginx still fails after fixing port:

1. **Check nginx.conf syntax:**
   ```bash
   docker compose exec nginx nginx -t
   ```

2. **Check if backend is reachable:**
   ```bash
   docker compose exec nginx curl http://backend:8000/api/v1/health
   ```

3. **Check if frontend is reachable:**
   ```bash
   docker compose exec nginx curl http://frontend:80
   ```

### If MongoDB won't start:

```bash
# Check MongoDB logs
docker compose logs mongodb

# Check if volume is corrupted
docker volume ls | grep hypersend
docker volume rm hypersend_mongodb_data  # WARNING: This deletes data!
```

### If Backend API fails:

```bash
# Check backend logs
docker compose logs -f backend

# Check if MongoDB connection works
docker compose exec backend python -c "
from pymongo import MongoClient
uri = 'mongodb://admin:changeme@mongodb:27017/hypersend?authSource=admin'
client = MongoClient(uri)
print('MongoDB connected:', client.admin.command('ping'))
"
```

---

## Prevention

To avoid this in the future:

1. **Always stop containers before making changes:**
   ```bash
   docker compose down
   ```

2. **Use health checks:**
   ```bash
   docker compose up -d --build
   docker compose ps  # Check STATUS
   ```

3. **Keep ports documented:**
   - Port 80: Nginx
   - Port 8000: Backend API
   - Port 27017: MongoDB

4. **Use environment-specific ports:**
   - Development: localhost:80
   - Staging: staging.example.com
   - Production: example.com (with proper SSL)

---

## Getting Help

If issue persists:

1. **Check Docker daemon is running**
2. **Check disk space:** `df -h`
3. **Check Docker status:** `docker ps`
4. **Restart Docker daemon** (last resort)

---

## Related Issues

- Port 8000 (Backend) already in use
- Port 27017 (MongoDB) already in use
- Port 443 (HTTPS) already in use

Use same troubleshooting steps but replace port number.

---

**Last Updated:** December 5, 2025
**Status:** Production Ready
