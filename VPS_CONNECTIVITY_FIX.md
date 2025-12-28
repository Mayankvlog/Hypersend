# VPS Connectivity Fix - Zaply Backend (zaply.in.net)

## Problem
Frontend login page shows RED ERROR banner:
```
Cannot connect to server. Please check:
1. Internet connection is active
2. Server is running (check: https://zaply.in.net)
3. API endpoint is reachable
```

## Root Causes & Fixes Applied ✅

### 1. **Frontend API URL Configuration** ✅ FIXED
**Problem:** Frontend was defaulting to `http://localhost:8004/api/v1/` instead of production URL
**File:** `frontend/lib/core/constants/api_constants.dart`
**Fix Applied:**
```dart
// BEFORE (Wrong)
defaultValue: 'http://localhost:8004/api/v1/',

// AFTER (Correct)
defaultValue: 'https://zaply.in.net/api/v1',
```

### 2. **Backend Port Configuration** ✅ FIXED
**Problem:** Backend config defaulted to port `8001` instead of `8000` (Nginx expects 8000)
**File:** `backend/config.py`
**Fix Applied:**
```python
# BEFORE (Wrong)
API_PORT: int = int(os.getenv("API_PORT", "8001"))
API_BASE_URL: str = os.getenv("API_BASE_URL", "https://zaply.in.net/api/v1/")

# AFTER (Correct)
API_PORT: int = int(os.getenv("API_PORT", "8000"))  # Nginx proxies to 8000
API_BASE_URL: str = os.getenv("API_BASE_URL", "https://zaply.in.net/api/v1")
```

### 3. **Better Error Messages** ✅ FIXED
**File:** `frontend/lib/data/services/api_service.dart`
**Enhancement:** Now shows specific server URLs and troubleshooting steps in error messages
```
Cannot connect to server. Please check:
1. ✓ Internet connection is active
2. Server is running: https://zaply.in.net
3. API endpoint (https://zaply.in.net/api/v1) is reachable

If you continue seeing this error:
• Verify: https://zaply.in.net/health
• Check VPS status and backend logs
```

### 4. **Enhanced Health Endpoint** ✅ FIXED
**File:** `backend/main.py`
**Enhancement:** Health endpoint now returns configuration info for debugging
```python
@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "zaply-api",
        "version": "1.0.0",
        "api_base_url": settings.API_BASE_URL,
        "api_host": settings.API_HOST,
        "api_port": settings.API_PORT,
        "debug": settings.DEBUG,
        "timestamp": "..."
    }
```

---

## Deployment Checklist

### Step 1: Rebuild Frontend with Correct API URL
```bash
# Local development (localhost backend on port 8000)
cd frontend
flutter clean
flutter pub get
flutter build web --release --dart-define=API_BASE_URL=http://localhost:8000/api/v1

# Production (zaply.in.net)
flutter clean
flutter pub get
flutter build web --release --dart-define=API_BASE_URL=https://zaply.in.net/api/v1
```

### Step 2: Update Docker Compose (if using containers)
```yaml
# docker-compose.yml backend service
environment:
  API_HOST: 0.0.0.0
  API_PORT: 8000              # ← Must be 8000
  API_BASE_URL: https://zaply.in.net/api/v1  # ← Production URL
  DEBUG: "False"
```

### Step 3: Verify Nginx Configuration
✅ Already correct in `nginx.conf`
- Proxies `/api/` requests to `backend:8000`
- HTTPS enabled with Let's Encrypt
- CORS headers configured

### Step 4: Start Backend Services
```bash
# Using Docker Compose
docker-compose up -d

# Verify backend is running
curl https://zaply.in.net/health

# Expected response:
# {
#   "status": "healthy",
#   "service": "zaply-api",
#   "version": "1.0.0",
#   "api_base_url": "https://zaply.in.net/api/v1",
#   "api_host": "0.0.0.0",
#   "api_port": 8000,
#   "debug": false,
#   "timestamp": "2025-12-28T..."
# }
```

---

## Troubleshooting Guide

### Test VPS Connectivity
Run the diagnostic test script:
```bash
cd c:\Users\mayan\Downloads\Addidas\hypersend
python test_vps_connectivity.py
```

This will check:
- DNS resolution (zaply.in.net → 139.59.82.105)
- HTTPS endpoints connectivity
- CORS headers
- API functionality
- Generate detailed report

### Common Issues & Solutions

#### 1. **"Cannot connect to server" - DNS Issue**
```bash
# Test DNS resolution
nslookup zaply.in.net
# Should resolve to: 139.59.82.105

# If not resolving, check:
# 1. Domain DNS settings at domain registrar
# 2. DNS propagation: https://www.whatsmydns.net/?domain=zaply.in.net
```

#### 2. **"Cannot connect to server" - Backend Down**
```bash
# SSH into VPS
ssh -i your-key.pem root@139.59.82.105

# Check Docker containers
docker-compose ps

# Expected: All containers running
# CONTAINER ID   IMAGE                  STATUS
# ...            hypersend_nginx        Up
# ...            hypersend_backend      Up
# ...            hypersend_frontend     Up
# ...            hypersend_mongodb      Up

# View backend logs
docker-compose logs -f backend

# Restart if needed
docker-compose restart backend
```

#### 3. **"SSL Certificate Error" - HTTPS Issue**
```bash
# Check certificate validity
curl -v https://zaply.in.net/health

# If cert expired, renew with Let's Encrypt
docker-compose exec nginx certbot renew

# Or manually:
certbot renew --standalone
```

#### 4. **"API endpoint not found" - Nginx Routing Issue**
```bash
# Check Nginx configuration
docker-compose exec nginx nginx -t

# View Nginx logs
docker-compose logs -f nginx

# Ensure backend is healthy
curl http://localhost:8000/health  # Inside Docker network
```

#### 5. **"Connection Refused" - Firewall Blocked**
```bash
# On VPS, check open ports
netstat -tuln | grep LISTEN
# Should show: 0.0.0.0:80, 0.0.0.0:443

# Check firewall rules (DigitalOcean Cloud Firewall)
# Ensure ports 80 and 443 are open to 0.0.0.0/0
```

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────┐
│                    USER BROWSER                         │
│              (Frontend - Flutter Web)                    │
│           https://zaply.in.net (Port 443)              │
└────────────────────┬────────────────────────────────────┘
                     │
                     │ HTTPS Request
                     │ https://zaply.in.net/api/v1/auth/login
                     │
        ┌────────────▼──────────────┐
        │    NGINX (Port 443)       │
        │  (Reverse Proxy)          │
        │  zaply.in.net             │
        └────────────┬──────────────┘
                     │
                     │ HTTP (Internal Docker Network)
                     │ http://backend:8000/api/v1/auth/login
                     │
        ┌────────────▼──────────────┐
        │   FastAPI Backend         │
        │   (Port 8000)             │
        │   hypersend_backend       │
        └────────────┬──────────────┘
                     │
                     │ MongoDB
                     │
        ┌────────────▼──────────────┐
        │   MongoDB (Port 27017)    │
        │   hypersend_mongodb       │
        └───────────────────────────┘

Key Points:
- Public: Only HTTPS on 443 (Nginx)
- Internal: HTTP on 8000 (Backend)
- All communication encrypted end-to-end
- Nginx handles SSL/TLS termination
```

---

## Environment Variables Reference

### Backend (docker-compose.yml)
```env
# API Configuration
API_HOST=0.0.0.0           # Listen on all interfaces
API_PORT=8000              # Backend port (Nginx proxies to this)
API_BASE_URL=https://zaply.in.net/api/v1  # Public URL

# Database
MONGO_HOST=mongodb         # Docker service name
MONGO_PORT=27017
MONGO_USER=hypersend
MONGO_PASSWORD=<your-password>

# Security
SECRET_KEY=<generate-with-secrets.token_urlsafe(64)>
DEBUG=False                # Production mode

# CORS
CORS_ORIGINS=*,https://zaply.in.net,https://www.zaply.in.net
```

### Frontend (Dockerfile or build command)
```bash
# Build flag for production
flutter build web --release --dart-define=API_BASE_URL=https://zaply.in.net/api/v1

# Or environment variable in docker-compose
API_BASE_URL=https://zaply.in.net/api/v1
```

---

## Verification Steps

### 1. Check Health Endpoint
```bash
# From your local machine
curl -k https://zaply.in.net/health

# Expected: HTTP 200 with JSON response
# {
#   "status": "healthy",
#   "service": "zaply-api",
#   ...
# }
```

### 2. Check API Endpoint
```bash
# Try login endpoint (will fail with invalid credentials, but that's OK)
curl -X POST https://zaply.in.net/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"test"}'

# Expected: HTTP 400/401/422 (not 503 or connection error)
```

### 3. Check Frontend
```bash
# Visit in browser
https://zaply.in.net

# Verify:
# - Page loads
# - No SSL warnings
# - Login attempt shows proper error (not "Cannot connect to server")
```

### 4. Check Logs
```bash
# Backend logs
docker-compose logs -f backend --tail 50

# Nginx logs
docker-compose logs -f nginx --tail 50

# MongoDB logs
docker-compose logs -f mongodb --tail 50
```

---

## Files Modified

1. **frontend/lib/core/constants/api_constants.dart**
   - Changed default API URL to `https://zaply.in.net/api/v1`

2. **backend/config.py**
   - Changed default port from 8001 to 8000
   - Removed trailing slash from API_BASE_URL

3. **frontend/lib/data/services/api_service.dart**
   - Enhanced error messages with server-specific URLs
   - Added troubleshooting hints

4. **backend/main.py**
   - Enhanced health endpoint with config info

5. **test_vps_connectivity.py** (NEW)
   - Comprehensive VPS connectivity test script

---

## Support & Monitoring

### Real-time Monitoring
```bash
# Watch all containers
docker-compose logs -f

# Watch backend only
docker-compose logs -f backend

# Watch specific service
docker-compose logs -f backend --since 10m
```

### Performance Check
```bash
# Backend response time
time curl https://zaply.in.net/health

# Load test (careful with production!)
ab -n 100 -c 10 https://zaply.in.net/health
```

### Security Check
```bash
# SSL/TLS grade
https://www.ssllabs.com/ssltest/analyze.html?d=zaply.in.net

# Security headers
curl -I https://zaply.in.net
```

---

## Next Steps

1. ✅ Code changes applied
2. 📦 Rebuild frontend with: `flutter build web --release --dart-define=API_BASE_URL=https://zaply.in.net/api/v1`
3. 🚀 Deploy containers: `docker-compose up -d`
4. 🧪 Run test: `python test_vps_connectivity.py`
5. 🌐 Test in browser: `https://zaply.in.net`

---

**Generated:** 2025-12-28
**VPS IP:** 139.59.82.105
**Domain:** zaply.in.net
**Status:** Configuration fixes applied ✅
