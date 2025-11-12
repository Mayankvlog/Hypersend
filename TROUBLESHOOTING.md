# 🔧 HyperSend Deployment Troubleshooting Guide

---

## 🚨 Common Issues & Solutions

### 1. GitHub Actions Deployment Fails

#### Issue: "Docker login failed"
```
Error: Error response from daemon: Get "https://registry-1.docker.io/v2/": 
unauthorized: incorrect username or password
```

**Solution:**
```bash
# 1. Verify DockerHub credentials
# Go to: https://hub.docker.com/settings/security
# Check if token is still valid

# 2. Regenerate token if needed
# Settings → Security → Access Tokens → New Access Token

# 3. Update GitHub Secrets
# Go to: GitHub Repository → Settings → Secrets
# Update: DOCKERHUB_TOKEN with new token

# 4. Re-run workflow
# GitHub → Actions → Select workflow → Run workflow
```

---

#### Issue: "VPS SSH connection failed"
```
Error: ssh: connect to host 123.45.67.89 port 22: Connection refused
```

**Solution:**
```bash
# 1. Verify VPS is running
# DigitalOcean Dashboard → Check droplet status

# 2. Check SSH credentials
# Verify VPS_HOST, VPS_USER, VPS_PASSWORD in GitHub Secrets

# 3. Test SSH manually
ssh -v root@YOUR_VPS_IP

# 4. If SSH key auth:
# Add SSH key to GitHub Secrets instead of password
# Use: appleboy/ssh-action with key parameter

# 5. Check firewall
# DigitalOcean → Networking → Firewalls
# Ensure port 22 is open
```

---

#### Issue: "Image build fails"
```
Error: failed to solve with frontend dockerfile.v0: 
failed to read dockerfile: open /var/lib/docker/tmp/...: no such file
```

**Solution:**
```bash
# 1. Check Dockerfile syntax
# Ensure Dockerfile exists in backend/ and frontend/

# 2. Verify build context
# Check .github/workflows/deploy-production.yml
# context: ./backend (should be correct)

# 3. Check for large files
# Remove unnecessary files from build context
# Create .dockerignore file

# 4. Increase Docker build timeout
# Edit workflow: timeout-minutes: 30

# 5. Clear Docker cache
# On VPS: docker system prune -a -f
```

---

### 2. Backend Container Won't Start

#### Issue: "Container exits immediately"
```
docker-compose ps
# backend: Exited (1) 5 seconds ago
```

**Solution:**
```bash
# 1. Check logs
docker-compose logs backend

# 2. Common causes:

# A) MongoDB connection failed
# Check MONGODB_URI in .env
# Verify format: mongodb+srv://user:pass@cluster.mongodb.net/db
# Test connection:
docker-compose exec backend python -c "
from backend.database import connect_db
import asyncio
asyncio.run(connect_db())
print('✅ Connected!')
"

# B) Port already in use
# Check what's using port 8000
lsof -i :8000
# Kill process if needed
kill -9 <PID>

# C) Missing environment variables
# Check .env file exists
# Verify all required variables are set
cat /root/Hypersend/.env

# D) Out of memory
# Check available memory
free -h
# Increase swap if needed
fallocate -l 8G /swapfile2
chmod 600 /swapfile2
mkswap /swapfile2
swapon /swapfile2

# 3. Restart container
docker-compose restart backend

# 4. Full restart
docker-compose down
docker-compose up -d
```

---

#### Issue: "ModuleNotFoundError: No module named 'backend'"
```
Error: ModuleNotFoundError: No module named 'backend'
```

**Solution:**
```bash
# 1. Check Dockerfile
# Ensure WORKDIR is set correctly
# Ensure requirements.txt is installed

# 2. Verify requirements.txt
cat backend/requirements.txt

# 3. Rebuild image
docker-compose build --no-cache backend

# 4. Restart
docker-compose restart backend
```

---

#### Issue: "Connection refused" when accessing API
```
curl: (7) Failed to connect to 123.45.67.89 port 8000: Connection refused
```

**Solution:**
```bash
# 1. Check if container is running
docker-compose ps backend

# 2. Check if port is exposed
docker-compose ps | grep 8000

# 3. Check firewall
ufw status
# Should show: 8000/tcp ALLOW

# 4. Check if service is listening
netstat -tulpn | grep 8000

# 5. Check logs
docker-compose logs backend

# 6. Restart
docker-compose restart backend

# 7. Test from inside container
docker-compose exec backend curl http://localhost:8000/health
```

---

### 3. Database Connection Issues

#### Issue: "MongoDB connection timeout"
```
Error: ServerSelectionTimeoutError: 
No servers found yet after waiting 30000ms
```

**Solution:**
```bash
# 1. Verify MongoDB URI format
# Should be: mongodb+srv://user:pass@cluster.mongodb.net/db
# Check for special characters in password (URL encode if needed)

# 2. Check MongoDB Atlas network access
# Go to: MongoDB Atlas → Network Access
# Verify your VPS IP is whitelisted
# Or add: 0.0.0.0/0 (allow from anywhere)

# 3. Test connection manually
docker-compose exec backend python << 'EOF'
import asyncio
from motor.motor_asyncio import AsyncClient

async def test():
    uri = "mongodb+srv://user:pass@cluster.mongodb.net/db"
    client = AsyncClient(uri)
    try:
        await client.admin.command('ping')
        print("✅ Connected!")
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        client.close()

asyncio.run(test())
EOF

# 4. Check credentials
# Verify username and password in MongoDB Atlas
# Database Access → Users

# 5. Verify cluster is running
# MongoDB Atlas Dashboard → Clusters
# Check cluster status

# 6. Check internet connectivity
docker-compose exec backend ping 8.8.8.8
```

---

#### Issue: "Authentication failed"
```
Error: authentication failed
```

**Solution:**
```bash
# 1. Verify credentials
# MongoDB Atlas → Database Access
# Check username and password

# 2. Check for special characters
# If password has special chars, URL encode them
# Example: @ becomes %40, # becomes %23

# 3. Verify database name
# Connection string should include database name
# mongodb+srv://user:pass@cluster.mongodb.net/hypersend

# 4. Reset password if needed
# MongoDB Atlas → Database Access → Edit User
# Generate new password

# 5. Update .env
nano /root/Hypersend/.env
# Update MONGODB_URI with new credentials

# 6. Restart
docker-compose restart backend
```

---

### 4. High CPU/Memory Usage

#### Issue: "CPU usage at 100%"
```
docker stats
# backend: 95% CPU
```

**Solution:**
```bash
# 1. Check what's consuming CPU
top -b -n 1 | head -20

# 2. Check backend logs for errors
docker-compose logs backend | tail -50

# 3. Common causes:

# A) Infinite loop in code
# Check recent code changes
git log --oneline -5

# B) Database query issue
# Check for slow queries
# Add indexes to MongoDB

# C) Memory leak
# Restart container
docker-compose restart backend

# 4. Monitor in real-time
docker stats backend

# 5. If persistent:
# Upgrade droplet
# Or optimize code
```

---

#### Issue: "Out of memory"
```
Error: Cannot allocate memory
```

**Solution:**
```bash
# 1. Check memory usage
free -h

# 2. Check Docker memory limits
docker stats

# 3. Increase swap
fallocate -l 8G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile

# 4. Clean up Docker
docker system prune -a -f

# 5. Reduce container memory usage
# Edit docker-compose.yml
# Reduce memory limits

# 6. Upgrade droplet
# DigitalOcean → Droplet → Resize
# Choose larger plan
```

---

### 5. Disk Space Issues

#### Issue: "No space left on device"
```
Error: No space left on device
```

**Solution:**
```bash
# 1. Check disk usage
df -h

# 2. Find large files
du -sh /root/Hypersend/*

# 3. Clean Docker
docker system prune -a -f

# 4. Remove old images
docker image prune -a -f

# 5. Remove old logs
docker-compose logs --tail=0 backend > /dev/null
# Or manually delete log files

# 6. Check data directory
du -sh /root/Hypersend/data/*

# 7. Archive old data
# Move old files to external storage
# Or delete if not needed

# 8. Upgrade droplet
# DigitalOcean → Droplet → Resize
# Choose larger storage
```

---

### 6. Network Issues

#### Issue: "Cannot reach VPS from internet"
```
curl: (7) Failed to connect to 123.45.67.89 port 8000
```

**Solution:**
```bash
# 1. Check firewall
ufw status
# Should show: 8000/tcp ALLOW

# 2. Add firewall rule if needed
ufw allow 8000/tcp
ufw reload

# 3. Check DigitalOcean firewall
# DigitalOcean Dashboard → Networking → Firewalls
# Ensure port 8000 is open

# 4. Check if service is listening
netstat -tulpn | grep 8000

# 5. Test from VPS
curl http://localhost:8000/health

# 6. Check routing
traceroute 8.8.8.8

# 7. Restart networking
systemctl restart networking
```

---

#### Issue: "Slow API response"
```
curl -w "@curl-format.txt" http://123.45.67.89:8000/health
# Response time: 5000ms (too slow)
```

**Solution:**
```bash
# 1. Check server load
top -b -n 1 | head -5

# 2. Check network latency
ping 8.8.8.8

# 3. Check database performance
# MongoDB Atlas → Metrics
# Look for slow queries

# 4. Check API logs
docker-compose logs backend | grep "GET\|POST"

# 5. Optimize:
# - Add caching
# - Optimize database queries
# - Add indexes
# - Upgrade droplet

# 6. Monitor response time
watch -n 5 'curl -w "Time: %{time_total}s\n" http://localhost:8000/health'
```

---

### 7. GitHub Actions Issues

#### Issue: "Workflow stuck in progress"
```
GitHub Actions → Workflow → Status: In Progress (for hours)
```

**Solution:**
```bash
# 1. Cancel workflow
# GitHub → Actions → Select workflow → Cancel run

# 2. Check for hanging processes
# On VPS: ps aux | grep docker

# 3. Kill hanging processes
kill -9 <PID>

# 4. Restart Docker
systemctl restart docker

# 5. Re-run workflow
# GitHub → Actions → Run workflow
```

---

#### Issue: "Health check fails after deployment"
```
Error: Health check failed
curl: (7) Failed to connect to 123.45.67.89 port 8000
```

**Solution:**
```bash
# 1. Wait longer for startup
# Services need time to initialize
# Increase sleep time in workflow

# 2. Check container status
docker-compose ps

# 3. Check logs
docker-compose logs backend

# 4. Verify environment variables
docker-compose exec backend env | grep MONGODB

# 5. Test health endpoint manually
curl http://localhost:8000/health

# 6. Restart containers
docker-compose restart backend
```

---

### 8. SSL/HTTPS Issues

#### Issue: "SSL certificate not found"
```
Error: SSL: CERTIFICATE_VERIFY_FAILED
```

**Solution:**
```bash
# 1. Check certificate
ls -la /etc/letsencrypt/live/yourdomain.com/

# 2. Renew certificate
certbot renew --force-renewal

# 3. Check certificate expiry
certbot certificates

# 4. Update nginx.conf
# Verify paths are correct:
# ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
# ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

# 5. Restart nginx
docker-compose restart nginx
```

---

#### Issue: "Mixed content warning"
```
Mixed Content: The page was loaded over HTTPS, 
but requested an insecure resource
```

**Solution:**
```bash
# 1. Update API_BASE_URL to use HTTPS
nano /root/Hypersend/.env
# Change: API_BASE_URL=https://yourdomain.com

# 2. Update nginx.conf
# Add redirect from HTTP to HTTPS

# 3. Restart services
docker-compose restart
```

---

### 9. Docker Issues

#### Issue: "Docker daemon not running"
```
Error: Cannot connect to Docker daemon
```

**Solution:**
```bash
# 1. Start Docker
systemctl start docker

# 2. Enable auto-start
systemctl enable docker

# 3. Check status
systemctl status docker

# 4. Check logs
journalctl -u docker -n 50

# 5. Restart if needed
systemctl restart docker
```

---

#### Issue: "Docker image pull fails"
```
Error: Error response from daemon: pull access denied
```

**Solution:**
```bash
# 1. Verify DockerHub login
docker login

# 2. Check image exists
# DockerHub → Repositories → Check image name

# 3. Verify image name format
# Should be: username/image-name:tag

# 4. Check DockerHub credentials
# Verify username and token

# 5. Re-login
docker logout
docker login

# 6. Pull manually
docker pull username/image-name:latest
```

---

### 10. Monitoring & Logging Issues

#### Issue: "Cannot view logs"
```
docker-compose logs backend
# Error: No such container
```

**Solution:**
```bash
# 1. Check if container exists
docker-compose ps

# 2. Check container name
# Should match service name in docker-compose.yml

# 3. Start container if stopped
docker-compose up -d backend

# 4. View logs
docker-compose logs -f backend

# 5. View specific number of lines
docker-compose logs --tail=100 backend
```

---

#### Issue: "Logs are too large"
```
Docker logs taking up too much disk space
```

**Solution:**
```bash
# 1. Check log size
du -sh /var/lib/docker/containers/*/

# 2. Limit log size in docker-compose.yml
# Add to service:
# logging:
#   driver: "json-file"
#   options:
#     max-size: "10m"
#     max-file: "3"

# 3. Rotate existing logs
docker-compose logs --tail=0 backend > /dev/null

# 4. Clean up old logs
find /var/lib/docker/containers -name "*.log" -mtime +7 -delete
```

---

## 🆘 Emergency Procedures

### Complete System Reset

```bash
# 1. Stop all containers
docker-compose down

# 2. Remove all Docker data
docker system prune -a -f

# 3. Remove volumes (WARNING: deletes data!)
docker volume prune -f

# 4. Restart Docker
systemctl restart docker

# 5. Pull fresh images
docker pull username/hypersend-backend:latest
docker pull username/hypersend-frontend:latest

# 6. Start fresh
docker-compose up -d
```

---

### Rollback to Previous Version

```bash
# 1. Check available image tags
docker images | grep hypersend

# 2. Stop current containers
docker-compose down

# 3. Update docker-compose.yml
# Change image tag to previous version
nano docker-compose.yml
# Change: image: username/hypersend-backend:latest
# To: image: username/hypersend-backend:previous-sha

# 4. Start with previous version
docker-compose up -d

# 5. Verify
docker-compose ps
```

---

### Backup & Restore

```bash
# Backup data
tar -czf /root/hypersend-backup-$(date +%Y%m%d).tar.gz /root/Hypersend/data/

# Restore data
tar -xzf /root/hypersend-backup-20240101.tar.gz -C /

# Backup MongoDB
mongodump --uri="mongodb+srv://user:pass@cluster.mongodb.net/hypersend" --out=/root/mongo-backup

# Restore MongoDB
mongorestore --uri="mongodb+srv://user:pass@cluster.mongodb.net/hypersend" /root/mongo-backup
```

---

## 📞 Getting Help

### Useful Commands for Debugging

```bash
# System info
uname -a
lsb_release -a

# Docker info
docker version
docker info

# Container info
docker-compose ps
docker-compose config

# Network info
netstat -tulpn
ss -tulpn

# Process info
ps aux | grep docker
ps aux | grep python

# Memory info
free -h
vmstat 1 5

# Disk info
df -h
du -sh /root/Hypersend/*

# Network connectivity
ping 8.8.8.8
curl -v http://localhost:8000/health
```

---

### Collect Debug Information

```bash
# Create debug report
cat > /root/debug_report.txt << 'EOF'
=== System Info ===
$(uname -a)

=== Docker Info ===
$(docker version)

=== Container Status ===
$(docker-compose ps)

=== Recent Logs ===
$(docker-compose logs --tail=50 backend)

=== Memory Usage ===
$(free -h)

=== Disk Usage ===
$(df -h)

=== Network Status ===
$(netstat -tulpn | grep LISTEN)
EOF

# View report
cat /root/debug_report.txt
```

---

## 📚 Additional Resources

- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [MongoDB Atlas Documentation](https://docs.atlas.mongodb.com/)
- [DigitalOcean Documentation](https://docs.digitalocean.com/)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)

---

**Still having issues?** Check the logs, run health checks, and verify all configurations!
