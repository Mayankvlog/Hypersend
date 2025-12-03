# Nginx Reverse Proxy Setup for Zaply

## Overview

Nginx acts as a reverse proxy (load balancer) that:
- Handles all incoming traffic on ports 80 (HTTP) and 443 (HTTPS)
- Routes `/api/` requests to the backend service
- Routes `/` (root) to the frontend service
- Manages rate limiting and security headers
- Supports large file uploads (up to 40GB)

## Architecture

```
Client (Browser/App)
    ↓
[Nginx on Port 80/443]
    ├─→ /api/* → Backend (Port 8000, Internal)
    └─→ /* → Frontend (Port 8550, Internal)
         ↓
    [MongoDB on Port 27017, Internal Only]
```

## Configuration Details

### 1. **Upstream Services** (Backend & Frontend)

The nginx.conf defines two upstream servers with keepalive:

```nginx
upstream backend_service {
    server backend:8000;      # Docker service name + port
    keepalive 32;             # Connection pooling
}

upstream frontend_service {
    server frontend:8550;
    keepalive 32;
}
```

### 2. **HTTP Server Block (Port 80)**

```nginx
server {
    listen 80;
    server_name _;    # Accept any hostname

    # Health endpoint for monitoring
    location /health {
        return 200 "ok\n";
    }

    # Backend API routing
    location /api/ {
        proxy_pass http://backend_service;
        # Headers, timeouts, buffering...
    }

    # Frontend routing (catch-all)
    location / {
        proxy_pass http://frontend_service;
        # Headers, WebSocket support...
    }
}
```

### 3. **Key Features**

#### Large File Upload Support
- `client_max_body_size 40G` - Support files up to 40GB
- `proxy_request_buffering off` - Stream uploads without buffering
- `proxy_buffering off` - Stream responses without buffering
- Timeout: 3600s (1 hour) - Enough for large uploads

#### Rate Limiting
```nginx
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=100r/s;
limit_req zone=api_limit burst=200 nodelay;
```
- Max 100 requests/second per IP
- Burst of 200 requests allowed

#### Gzip Compression
```nginx
gzip on;
gzip_comp_level 6;
gzip_types text/*, application/json, application/javascript;
```
- Reduces bandwidth by ~70% for text/JSON responses

#### WebSocket Support
```nginx
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";
```
- Enables real-time features (chat, notifications)

#### Security Headers (Prepared for HTTPS)
```nginx
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
```

## Deployment

### Using Docker Compose

1. **Copy .env template:**
   ```bash
   cp .env.example .env
   ```

2. **Start services:**
   ```bash
   docker-compose up -d
   ```

3. **Verify nginx is running:**
   ```bash
   docker ps | grep nginx
   docker logs hypersend_nginx
   ```

### Service Stack

```yaml
services:
  nginx:                    # Reverse proxy
    image: nginx:alpine
    ports: [80:80, 443:443]
    volumes: [nginx.conf]
    depends_on: [backend, frontend]
  
  backend:                  # API
    image: hypersend-backend
    ports: [8000]           # Internal only
    depends_on: [mongodb]
  
  frontend:                 # Web UI
    image: hypersend-frontend
    ports: [8550]           # Internal only
    depends_on: [backend]
  
  mongodb:                  # Database
    image: mongo:7.0
    ports: [27017]          # Internal only
```

## Access Endpoints

| Service | URL | Port | Notes |
|---------|-----|------|-------|
| Frontend | http://VPS_IP | 80 | Public access |
| Backend API | http://VPS_IP/api/ | 80 | Public via nginx |
| Health Check | http://VPS_IP/health | 80 | Returns "ok" |
| Backend Direct | http://VPS_IP:8000 | 8000 | Direct (bypasses nginx) |
| Frontend Direct | http://VPS_IP:8550 | 8550 | Direct (bypasses nginx) |

**Recommended: Always use port 80 (via nginx) for production**

## Troubleshooting

### 1. **502 Bad Gateway Error**

**Cause:** Nginx can't connect to backend/frontend

**Solution:**
```bash
# Check if backend/frontend are running
docker-compose ps

# Check nginx logs
docker logs hypersend_nginx

# Test backend connectivity from nginx container
docker exec hypersend_nginx wget -O- http://backend:8000/health

# Restart services
docker-compose restart
```

### 2. **Nginx Config Syntax Error**

**Cause:** Invalid nginx.conf file

**Solution:**
```bash
# Validate nginx config
docker exec hypersend_nginx nginx -t

# Fix errors and reload
docker-compose restart nginx
```

### 3. **413 Payload Too Large**

**Cause:** File upload exceeds `client_max_body_size`

**Solution:** Already set to 40GB in nginx.conf

```bash
# Verify in config
grep client_max_body_size nginx.conf
# Output: client_max_body_size 40G;
```

### 4. **504 Gateway Timeout**

**Cause:** Upload/download taking longer than proxy timeout

**Solution:** Already set to 3600s (1 hour) in nginx.conf

```bash
# Verify in config
grep proxy_read_timeout nginx.conf
# Output: proxy_read_timeout 3600s;
```

### 5. **Connection Refused on Port 80**

**Cause:** Nginx container not running or port already in use

**Solution:**
```bash
# Check if port 80 is in use
lsof -i :80  # Linux/Mac
netstat -ano | findstr :80  # Windows

# Check nginx container
docker logs hypersend_nginx

# Restart nginx
docker-compose restart nginx
```

## HTTPS Setup (Production)

For production with SSL certificates from Let's Encrypt:

1. **Get SSL certificates:**
   ```bash
   docker run --rm -it \
     -v $(pwd)/ssl:/etc/letsencrypt \
     -p 80:80 \
     certbot/certbot certonly --standalone \
     -d your-domain.com
   ```

2. **Update nginx.conf:**
   - Uncomment the HTTPS server block
   - Update `server_name api.yourdomain.com`
   - Update SSL certificate paths
   - Add HTTP→HTTPS redirect

3. **Reload nginx:**
   ```bash
   docker-compose restart nginx
   ```

## Monitoring

### Check Health Endpoint
```bash
curl http://139.59.82.105/health
# Expected output: ok
```

### Monitor Logs
```bash
# Nginx access logs
docker logs -f hypersend_nginx

# Real-time access monitoring
docker exec hypersend_nginx tail -f /var/log/nginx/access.log
```

### Check Upstream Services
```bash
# Backend health
curl http://139.59.82.105/api/v1/health

# Frontend status
curl -L http://139.59.82.105
```

## Performance Tips

1. **Enable Caching (in nginx.conf):**
   ```nginx
   proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=api_cache:10m;
   proxy_cache api_cache;
   proxy_cache_valid 200 1m;
   ```

2. **Use CDN for Static Files:**
   ```nginx
   location /static/ {
       expires 30d;
       add_header Cache-Control "public, immutable";
   }
   ```

3. **Rate Limiting:**
   Already configured at 100 req/s per IP

4. **Connection Pooling:**
   - Upstream: `keepalive 32`
   - Backend HTTP/1.1 with Connection: ""

## Files Modified

1. **nginx.conf** - Main reverse proxy configuration
2. **docker-compose.yml** - Added nginx service
3. **.env.example** - Added port documentation

## Status

✅ Nginx reverse proxy properly configured
✅ Backend routing to /api/
✅ Frontend routing to /
✅ Large file upload support (40GB)
✅ Health check endpoint
✅ Rate limiting enabled
✅ WebSocket support enabled
✅ HTTPS commented out (ready to uncomment)

---

**Next Steps:**
1. Deploy: `docker-compose up -d`
2. Test: `curl http://VPS_IP/health`
3. Monitor: `docker logs -f hypersend_nginx`
4. Setup HTTPS when ready (see HTTPS Setup section above)
