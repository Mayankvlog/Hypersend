# Hypersend Docker Deployment - Complete Setup Guide

## Pre-Requisites

- Docker & Docker Compose installed
- Linux server (Ubuntu 20.04+) or macOS/Windows with Docker Desktop
- Port 80 (HTTP) and 443 (HTTPS) available or configurable

---

## Installation Steps

### 1. Clone Repository
```bash
git clone https://github.com/Mayankvlog/Hypersend.git
cd Hypersend
```

### 2. Setup Environment
```bash
# Copy example environment file
cp .env.example .env

# Edit .env with your settings
nano .env  # or use your preferred editor
```

### 3. Configure Ports (If Port 80 is Busy)

If port 80 is already in use, edit `.env`:

```bash
# Change NGINX_PORT to an available port
NGINX_PORT=8080    # Instead of 80
NGINX_PORT_SSL=8443  # Instead of 443
```

Then access the app at: `http://localhost:8080`

### 4. Pull Latest Images
```bash
docker compose pull
```

### 5. Build and Start Services
```bash
docker compose up -d --build
```

### 6. Verify Services are Running
```bash
docker compose ps
```

Expected output:
```
NAME                 STATUS         PORTS
hypersend_mongodb    running        27017/tcp
hypersend_backend    running        8000/tcp
hypersend_frontend   running        80/tcp
hypersend_nginx      running        0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp
```

---

## Troubleshooting

### Port 80 Already in Use

**Problem:**
```
Error: failed to bind host port 0.0.0.0:80/tcp: address already in use
```

**Solutions:**

#### Option 1: Use Different Port (Recommended)
Edit `.env`:
```bash
NGINX_PORT=8080
NGINX_PORT_SSL=8443
```

Then:
```bash
docker compose down
docker compose up -d --build
# Access at http://localhost:8080
```

#### Option 2: Free Port 80 (Linux)
```bash
# Check what's using port 80
sudo lsof -i :80
# or
sudo netstat -tlnp | grep :80

# Stop the service
sudo systemctl stop apache2  # or nginx, httpd, etc
sudo systemctl disable apache2  # Prevent auto-start

# Or kill specific process
sudo kill -9 <PID>
```

#### Option 3: Use Docker Fix Scripts
```bash
# Linux/macOS
chmod +x fix_port_conflict.sh
./fix_port_conflict.sh

# Windows
fix_port_conflict.bat
```

---

## Access Application

- **Frontend:** http://localhost (or http://localhost:8080 if using port 8080)
- **API Docs:** http://localhost/api/v1/docs
- **API Base URL:** http://localhost/api/v1

---

## Common Commands

### View Logs
```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f nginx
docker compose logs -f backend
docker compose logs -f mongodb
docker compose logs -f frontend
```

### Restart Services
```bash
# Restart all
docker compose restart

# Restart specific service
docker compose restart backend
```

### Stop Services
```bash
docker compose stop
```

### Complete Cleanup (WARNING: Deletes data!)
```bash
docker compose down -v
```

### Rebuild Containers
```bash
docker compose down
docker compose build --no-cache
docker compose up -d
```

---

## Database Access

### MongoDB Connection
```bash
# Local connection
mongodb://admin:changeme@localhost:27017/hypersend?authSource=admin

# From inside container
docker compose exec mongodb mongosh -u admin -p changeme
```

### Backup MongoDB
```bash
docker compose exec mongodb mongodump --uri="mongodb://admin:changeme@localhost:27017" --out=/backup
```

---

## Environment Variables Reference

| Variable | Default | Purpose |
|----------|---------|---------|
| `NGINX_PORT` | 80 | HTTP port |
| `NGINX_PORT_SSL` | 443 | HTTPS port |
| `MONGO_USER` | admin | MongoDB username |
| `MONGO_PASSWORD` | changeme | MongoDB password |
| `SECRET_KEY` | (set in .env) | JWT secret |
| `ENVIRONMENT` | dev | dev or prod |

---

## Production Deployment

### 1. Update Environment Variables
```bash
# .env for production
NGINX_PORT=80
NGINX_PORT_SSL=443
MONGO_PASSWORD=your-strong-password
SECRET_KEY=your-generated-secret-key
ENVIRONMENT=prod
```

### 2. Enable HTTPS
Update `nginx.conf` with SSL certificates

### 3. Health Checks
```bash
# Check container health
docker compose ps

# Monitor services
docker compose stats
```

### 4. Security Checklist
- [ ] Change default MongoDB password
- [ ] Set strong SECRET_KEY
- [ ] Enable SSL/TLS certificates
- [ ] Configure firewall rules
- [ ] Setup automatic backups
- [ ] Enable Docker logging
- [ ] Setup monitoring/alerts

---

## Updating Application

### Pull Latest Code
```bash
git pull origin main
```

### Rebuild and Restart
```bash
docker compose down
docker compose pull
docker compose up -d --build
```

---

## Performance Optimization

### Increase Docker Memory
Edit `docker-compose.yml`:
```yaml
services:
  backend:
    deploy:
      resources:
        limits:
          memory: 2G
        reservations:
          memory: 1G
```

### Enable Docker BuildKit (Faster Builds)
```bash
DOCKER_BUILDKIT=1 docker compose build
```

---

## Issue Resolution

### Container Won't Start
```bash
# Check logs
docker compose logs <service_name>

# Rebuild
docker compose build --no-cache
docker compose up -d
```

### Permission Denied Errors
```bash
# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker
```

### Network Connectivity Issues
```bash
# Inspect network
docker network inspect hypersend_hypersend_network

# Restart network
docker network prune
docker compose down
docker compose up -d
```

---

## Support & Documentation

- **GitHub:** https://github.com/Mayankvlog/Hypersend
- **Issues:** https://github.com/Mayankvlog/Hypersend/issues
- **API Docs:** http://localhost/api/v1/docs (when running)

---

## Version Info

- Docker Compose Format: 3.0+ (version removed - using latest)
- Python: 3.11
- MongoDB: 7.0
- Nginx: Alpine
- Last Updated: December 5, 2025
