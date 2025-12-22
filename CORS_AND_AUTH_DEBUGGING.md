# Zaply API Debugging Guide - NS_ERROR_GENERATE_FAILURE Fix

## 🔍 Current Status

Your configuration is **almost perfect**, but there are a few potential issues causing the NS_ERROR:

### What's Working ✅
1. **Frontend URL**: Correctly calling `https://zaply.in.net/api/v1/chats/`
2. **CORS**: FastAPI has CORSMiddleware configured with `https://zaply.in.net` in allow_origins
3. **Nginx**: Properly forwarding `/api/` to backend with all headers
4. **Auth**: HTTPBearer security with JWT tokens is in place
5. **Endpoint**: `GET /chats/` exists and requires auth

### Potential Issues ⚠️

---

## Issue #1: CORS Preflight Requests May Fail

### Problem
Browser makes OPTIONS preflight request before GET, but your endpoint requires authentication (`@router.get("/")` with `Depends(get_current_user)`).

CORS preflight requests don't have auth headers, so FastAPI rejects them with 401 before CORSMiddleware can respond.

### Evidence
```
Network tab shows:
OPTIONS /api/v1/chats/ → 401 Unauthorized (or dropped)
GET /api/v1/chats/ → (never sent because preflight failed)
```

### Fix
Add a CORS preflight handler that bypasses auth for OPTIONS requests:

**File: `backend/main.py`** - Add before route registration:

```python
# Fix CORS preflight by handling OPTIONS without auth
from fastapi import Request

@app.options("/{full_path:path}")
async def preflight(request: Request, full_path: str):
    """Handle CORS preflight requests"""
    return Response(status_code=204)
```

**Full updated section of main.py:**

```python
# ... existing CORS middleware code ...

# CORS middleware - configured from settings to respect DEBUG/PRODUCTION modes
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition", "X-Total-Count"],
    max_age=600,  # Cache preflight requests for 10 minutes
)

# ✅ ADD THIS: Handle CORS preflight without auth
@app.options("/{full_path:path}")
async def handle_options(full_path: str):
    """Handle CORS preflight requests - no auth required"""
    return Response(status_code=204)

# Security headers middleware
@app.middleware("http")
async def add_security_headers(request, call_next):
    # ... rest of middleware code ...
```

---

## Issue #2: Missing Content-Type Header in Preflight

### Problem
Browser preflight may be missing `Content-Type: application/json` header.

### Fix in Nginx

Add content-type handling in `nginx.conf` location `/api/`:

```nginx
location /api/ {
    proxy_pass http://backend:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-Port 443;
    proxy_set_header Authorization $http_authorization;
    
    # ✅ ADD THIS: Ensure Content-Type is forwarded
    proxy_set_header Content-Type $http_content_type;
    
    # Allow empty auth header for OPTIONS requests
    proxy_set_header Authorization $http_authorization;
    
    # ... rest of proxy config ...
}
```

---

## Issue #3: Backend Secret Key May Have Changed

### Problem
If you restarted backend and SECRET_KEY was not in `.env`, it auto-generates a new one, invalidating all existing tokens.

### Evidence
```
Browser has stored token from old session
Token was signed with old SECRET_KEY
Backend started with new SECRET_KEY
Token validation fails: "Could not validate credentials"
→ 401 Unauthorized → Browser can't reach API
```

### Fix

Ensure `.env` file has persistent SECRET_KEY:

**File: `.env`**
```
SECRET_KEY=your-persistent-secret-key-at-least-32-chars-long-change-in-production
DEBUG=False
PRODUCTION_API_URL=https://zaply.in.net/api/v1
# ... rest of env vars
```

**Then restart backend:**
```bash
docker compose restart backend
```

---

## Issue #4: CORS Origin Not Exactly Matching

### Problem
Browser origin: `https://zaply.in.net`  
But CORS allows: `https://zaply.in.net:443` (with port)

### Check in `backend/config.py`

```python
CORS_ORIGINS: list = [
    # ... other origins ...
    "https://zaply.in.net",  # ✅ CORRECT - no port
    # ❌ NOT "https://zaply.in.net:443"  - port is not needed for HTTPS
    # ❌ NOT "http://zaply.in.net"  - must be HTTPS in production
]
```

If using wildcard in development (temporary fix):
```python
# Only for debugging - remove in production!
CORS_ORIGINS: list = ["*"] if settings.DEBUG else [
    "https://zaply.in.net",
    # ... other origins ...
]
```

---

## Comprehensive Diagnostic Steps

### Step 1: Check Browser Console
```javascript
// In browser DevTools console
fetch('https://zaply.in.net/api/v1/chats/', {
  method: 'GET',
  headers: {
    'Authorization': 'Bearer YOUR_TOKEN_HERE',
    'Content-Type': 'application/json'
  }
}).then(r => r.json()).then(console.log).catch(console.error);
```

### Step 2: Check Backend Logs
```bash
docker compose logs backend -f --tail=100
# Look for:
# - "[API_ERROR] Network/Connection error"
# - "401 Unauthorized"
# - "Could not validate credentials"
# - "Token has expired"
```

### Step 3: Check Nginx Logs
```bash
docker compose logs nginx -f --tail=50
# Look for:
# - Failed upstream (backend not responding)
# - Timeouts
# - Bad gateway
```

### Step 4: Test Backend Directly (from VPS)
```bash
# Get auth token first
curl -X POST http://localhost:8000/api/v1/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password"}' \
  2>/dev/null | jq '.access_token'

# Use token to test chats endpoint
TOKEN="your_token_here"
curl -X GET http://localhost:8000/api/v1/chats/ \
  -H "Authorization: Bearer $TOKEN" \
  2>/dev/null | jq '.'
```

### Step 5: Test Nginx Proxy
```bash
# Test from outside (your local machine)
curl -v https://zaply.in.net/api/v1/chats/ \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"

# Look for:
# - 200 OK vs 401 vs 500
# - CORS headers in response
```

---

## Complete Fixed Backend Configuration

### `backend/main.py` - Full Section

```python
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pathlib import Path
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from database import connect_db, close_db
from routes import auth, files, chats, users, updates, p2p_transfer, groups, messages, channels
from config import settings
from mongo_init import ensure_mongodb_ready
from security import SecurityConfig

# ... lifespan context manager code (unchanged) ...

app = FastAPI(
    title="Zaply API",
    description="Secure peer-to-peer file transfer and messaging application",
    version="1.0.0",
    lifespan=lifespan
)

# TrustedHost middleware
if not settings.DEBUG and os.getenv("ENABLE_TRUSTED_HOST", "false").lower() == "true":
    allowed_hosts = os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=allowed_hosts
    )

# ✅ CORS middleware with explicit configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],  # ✅ Explicitly include OPTIONS
    allow_headers=["*"],
    expose_headers=["Content-Disposition", "X-Total-Count"],
    max_age=3600,  # Cache preflight for 1 hour
)

# ✅ Handle CORS preflight without requiring authentication
@app.options("/{full_path:path}")
async def handle_options_request(request: Request, full_path: str):
    """
    Handle CORS preflight OPTIONS requests.
    These must succeed without authentication for CORS to work in browsers.
    """
    return Response(
        status_code=204,
        headers={
            "Access-Control-Allow-Origin": request.headers.get("origin", "*"),
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Max-Age": "3600",
        }
    )

# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    
    security_headers = SecurityConfig.get_security_headers()
    
    if not request.url.scheme == "https":
        security_headers.pop("Strict-Transport-Security", None)
    
    for header, value in security_headers.items():
        response.headers[header] = value
    
    return response

# ... rest of endpoints and router registration (unchanged) ...
```

### `nginx.conf` - Updated /api/ Location Block

```nginx
location /api/ {
    proxy_pass http://backend:8000;
    
    # ✅ Core headers for proxying
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-Port 443;
    
    # ✅ Authorization header (essential for auth)
    proxy_set_header Authorization $http_authorization;
    
    # ✅ Content-Type header
    proxy_set_header Content-Type $http_content_type;
    
    # WebSocket support
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    
    # Timeouts for large uploads/downloads
    proxy_connect_timeout 60s;
    proxy_send_timeout 3600s;
    proxy_read_timeout 3600s;
    
    # Buffering
    proxy_buffering off;
    proxy_request_buffering off;
    
    # ✅ Allow empty Authorization header for OPTIONS requests
    proxy_set_header Authorization $http_authorization;
}
```

---

## Testing Checklist

- [ ] Backend logs show no 401 errors
- [ ] Browser DevTools Network tab shows OPTIONS → 204
- [ ] Browser DevTools Network tab shows GET → 200
- [ ] Response body contains `{"chats": [...]}`
- [ ] No CORS errors in browser console
- [ ] Direct `curl` test from VPS succeeds
- [ ] `.env` file has persistent `SECRET_KEY`
- [ ] Backend restarted after code changes

---

## Quick Fix Summary

1. **Add CORS preflight handler** to `backend/main.py`
2. **Verify `.env` has SECRET_KEY** (not auto-generated)
3. **Update nginx.conf** to forward Content-Type header
4. **Restart services**:
   ```bash
   docker compose down
   docker compose up -d
   ```
5. **Test browser reload** at https://zaply.in.net/#/chats

---

## If Still Not Working

Get the exact error:
```bash
# Terminal 1: Watch backend logs
docker compose logs backend -f

# Terminal 2: Watch nginx logs
docker compose logs nginx -f

# Terminal 3: Browser reload at https://zaply.in.net/#/chats
# Check DevTools Console for exact error message
```

Then share:
1. Exact error message from browser console
2. Backend log output from step above
3. Nginx log output from step above
