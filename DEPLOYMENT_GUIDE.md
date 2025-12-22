# Zaply - Complete Production Deployment Guide
**For DigitalOcean VPS with Docker Compose, FastAPI, MongoDB, Flutter Web, and Let's Encrypt SSL**

---

## Quick Start

```bash
# 1. SSH into your VPS
ssh root@your-vps-ip

# 2. Clone the repository
mkdir -p /root/hypersend && cd /root/hypersend
git clone https://github.com/Mayankvlog/Hypersend.git .

# 3. Create .env file with secrets
cat > .env << 'EOF'
MONGO_USER=hypersend
MONGO_PASSWORD=$(openssl rand -base64 32)
SECRET_KEY=$(openssl rand -base64 32)
API_BASE_URL=https://zaply.in.net/api/v1
CORS_ORIGINS=https://zaply.in.net,http://zaply.in.net
DEBUG=False
EOF

# 4. Verify DNS and Let's Encrypt certificates exist
ls -la /etc/letsencrypt/live/zaply.in.net/

# 5. Deploy all services
docker compose up -d --build

# 6. Monitor deployment
docker compose logs -f --tail=50
```

---

## Architecture Overview

```
Internet (HTTPS)
    ↓ zaply.in.net:443
┌─────────────────────────────────────────┐
│  Nginx (reverse proxy + SSL termination) │
└─────────┬─────────────────┬─────────────┘
          │                 │
   /api/* │                 │ /
          ↓                 ↓
┌──────────────────┐  ┌─────────────────┐
│ FastAPI Backend  │  │ Flutter Web App │
│ (backend:8000)   │  │ (frontend:80)   │
│ - JWT Auth       │  │ - Material3 UI  │
│ - File Transfer  │  │ - Dio HTTP      │
└────────┬─────────┘  └─────────────────┘
         │
         │ mongodb://user:pass@mongodb:27017
         ↓
    ┌──────────────┐
    │   MongoDB    │
    │ (27017)      │
    └──────────────┘
    (No public access)

All services communicate via Docker network (172.20.0.0/16)
```

---

## Backend Configuration

### MongoDB Connection (`backend/database.py`)

Uses Motor (async MongoDB driver) with Docker service name for connection:

```python
from motor.motor_asyncio import AsyncIOMotorClient
from config import settings

async def connect_db():
    """Connect to MongoDB via Docker service name 'mongodb'"""
    global client, db
    try:
        # MONGODB_URI from environment variable
        # mongodb://{MONGO_USER}:{MONGO_PASSWORD}@mongodb:27017/hypersend?authSource=admin&retryWrites=true
        client = AsyncIOMotorClient(
            settings.MONGODB_URI,
            serverSelectionTimeoutMS=5000,
            connectTimeoutMS=5000,
            socketTimeoutMS=5000
        )
        await client.admin.command('ping')
        db = client.hypersend
        print(f"[OK] Connected to MongoDB")
    except Exception as e:
        print(f"[ERROR] Failed to connect to MongoDB: {str(e)}")
        raise
```

**Key Points:**
- Service name: `mongodb` (Docker internal network)
- Auth: `authSource=admin` (MongoDB root database)
- Password: URL-encoded (@=%40, #=%23, etc.)

---

### CORS Middleware (`backend/main.py`)

```python
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://zaply.in.net", "http://zaply.in.net"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition", "X-Total-Count"],
    max_age=3600,
)

# Handle CORS preflight (OPTIONS) without requiring auth
@app.options("/{full_path:path}")
async def handle_options(full_path: str):
    """Browser sends OPTIONS before GET/POST for CORS preflight"""
    return Response(status_code=204)

@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "healthy"}
```

---

### Protected Routes with Auth (`backend/routes/chats.py`)

```python
from fastapi import APIRouter, Depends
from auth.utils import get_current_user

router = APIRouter(prefix="/chats", tags=["Chats"])

@router.get("/")
async def list_chats(current_user: str = Depends(get_current_user)):
    """
    List all chats for the current user.
    Requires: Authorization: Bearer <JWT_TOKEN>
    """
    chats = await db.chats.find({"members": current_user}).to_list(None)
    return {"chats": chats}
```

**Auth Dependency** (`backend/auth/utils.py`):

```python
from fastapi.security import HTTPBearer, HTTPAuthCredential
from jose import jwt, JWTError

security = HTTPBearer()

async def get_current_user(credentials: HTTPAuthCredential = Depends(security)) -> str:
    """Validate JWT token from Authorization: Bearer <token>"""
    token = credentials.credentials
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        return user_id
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
```

---

## Frontend Configuration

### API Base URL (`frontend/lib/core/constants/api_constants.dart`)

```dart
class ApiConstants {
  // Production: https://zaply.in.net/api/v1
  // Passed via --dart-define=API_BASE_URL during Docker build
  static const String baseUrl = String.fromEnvironment(
    'API_BASE_URL',
    defaultValue: 'https://zaply.in.net/api/v1',
  );
  
  static const String authEndpoint = 'auth';
  static const String chatsEndpoint = 'chats';
  static const String usersEndpoint = 'users';
  static const String filesEndpoint = 'files';
  
  static const Duration connectTimeout = Duration(seconds: 30);
  static const Duration receiveTimeout = Duration(seconds: 30);
}
```

### Dio HTTP Client (`frontend/lib/data/services/api_service.dart`)

```dart
class ApiService {
  late Dio _dio;

  ApiService() {
    _dio = Dio(
      BaseOptions(
        baseUrl: ApiConstants.baseUrl,  // https://zaply.in.net/api/v1
        connectTimeout: ApiConstants.connectTimeout,
        receiveTimeout: ApiConstants.receiveTimeout,
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
      ),
    );

    // Add interceptor to attach JWT token
    _dio.interceptors.add(
      InterceptorsWrapper(
        onRequest: (options, handler) async {
          final token = await _tokenService.getAccessToken();
          if (token != null) {
            options.headers['Authorization'] = 'Bearer $token';  // Important!
          }
          return handler.next(options);
        },
      ),
    );
  }

  // API calls with trailing slashes (FastAPI requirement)
  Future<LoginResponse> login(String email, String password) async {
    final response = await _dio.post(
      '${ApiConstants.authEndpoint}/login/',  // /api/v1/auth/login/
      data: {'email': email, 'password': password},
    );
    return LoginResponse.fromJson(response.data);
  }

  Future<List<Chat>> getChats() async {
    final response = await _dio.get('${ApiConstants.chatsEndpoint}/');  // /api/v1/chats/
    return (response.data['chats'] as List)
        .map((c) => Chat.fromJson(c))
        .toList();
  }
}
```

### Frontend Dockerfile

```dockerfile
# Build stage
FROM debian:bookworm-slim AS build

RUN apt-get update && apt-get install -y curl git unzip xz-utils zip && rm -rf /var/lib/apt/lists/*

# Install Flutter 3.35.6
RUN git clone --depth 1 --branch 3.35.6 https://github.com/flutter/flutter.git /opt/flutter

ENV FLUTTER_HOME=/opt/flutter
ENV PATH="$FLUTTER_HOME/bin:$PATH"
ENV FLUTTER_SUPPRESS_ANALYTICS=true

RUN flutter precache --web && flutter config --enable-web

WORKDIR /app
COPY pubspec.yaml pubspec.lock ./
RUN flutter pub get

COPY . .

# Build with API_BASE_URL (passed from docker-compose.yml)
ARG API_BASE_URL=https://zaply.in.net/api/v1
RUN flutter build web --release --no-tree-shake-icons \
    --dart-define=API_BASE_URL=${API_BASE_URL}

# Serve stage
FROM nginx:alpine
COPY --from=build /app/build/web /usr/share/nginx/html

RUN rm -f /etc/nginx/conf.d/default.conf && \
    echo 'server { \
        listen 80; \
        root /usr/share/nginx/html; \
        index index.html; \
        location / { try_files $uri $uri/ /index.html; } \
        location /health { return 200 "healthy\n"; add_header Content-Type text/plain; } \
    }' > /etc/nginx/conf.d/default.conf

EXPOSE 80
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://127.0.0.1/health || exit 1

CMD ["nginx", "-g", "daemon off;"]
```

---

## Docker Compose & Nginx Configuration

See the updated files in the repository:
- **docker-compose.yml** - Updated with production settings (no unnecessary port exposures)
- **nginx.conf** - Updated with Let's Encrypt certificate paths

Key changes:
- ✅ Backend port 8000 NOT exposed to host
- ✅ Frontend port 80 NOT exposed to host (Nginx proxies)
- ✅ MongoDB port 27017 NOT exposed to host
- ✅ Only Nginx ports 80/443 exposed
- ✅ Using `/etc/letsencrypt/` certs from host
- ✅ DEBUG=False (production mode)

---

## DigitalOcean VPS Deployment

### Prerequisites

```bash
# Update system
sudo apt-get update && sudo apt-get upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
newgrp docker

# Verify Docker Compose
docker compose version

# Install utilities
sudo apt-get install -y git curl openssl
```

### Setup Let's Encrypt (If needed)

```bash
# Install Certbot
sudo apt-get install -y certbot python3-certbot-nginx

# Get certificate
sudo certbot certonly --standalone -d zaply.in.net

# Verify certs
ls -la /etc/letsencrypt/live/zaply.in.net/
```

### Deployment Steps

```bash
# 1. SSH and navigate
ssh root@your-vps-ip
cd /root && mkdir -p hypersend && cd hypersend

# 2. Clone repo
git clone https://github.com/Mayankvlog/Hypersend.git .

# 3. Create .env file
cat > .env << 'EOF'
MONGO_USER=hypersend
MONGO_PASSWORD=$(openssl rand -base64 32)
SECRET_KEY=$(openssl rand -base64 32)
API_BASE_URL=https://zaply.in.net/api/v1
CORS_ORIGINS=https://zaply.in.net,http://zaply.in.net
DEBUG=False
EOF

# Edit .env and set actual values
nano .env  # Change MONGO_PASSWORD and SECRET_KEY to real values

# 4. Verify DNS
nslookup zaply.in.net

# 5. Verify Let's Encrypt
ls -la /etc/letsencrypt/live/zaply.in.net/

# 6. Deploy
docker compose up -d --build

# 7. Monitor
docker compose logs -f --tail=100
```

---

## Verification Checklist

```bash
# Service status
docker compose ps
# All should show: (healthy)

# HTTP redirect
curl -i http://zaply.in.net/health
# Expected: 301 Moved Permanently

# HTTPS health
curl -i https://zaply.in.net/health
# Expected: 200 healthy

# Backend API health
curl -i https://zaply.in.net/api/v1/health
# Expected: 200 {"status":"healthy"}

# Frontend loads
curl -s https://zaply.in.net/ | head -20
# Should contain: <html>, Flutter web app

# CORS preflight
curl -i -X OPTIONS https://zaply.in.net/api/v1/chats/ \
  -H "Origin: https://zaply.in.net" \
  -H "Access-Control-Request-Method: GET"
# Expected: 204 with Access-Control headers
```

---

## Test in Browser

1. Open: `https://zaply.in.net`
2. Should show Flutter Material3 UI
3. Open DevTools (F12) → Network tab
4. Login with test credentials
5. Verify network requests:
   - All API calls go to `https://zaply.in.net/api/v1/*`
   - Auth header: `Authorization: Bearer <token>`
   - Status: 200 OK (no NS_ERROR)

---

## Troubleshooting

**Services won't start:**
```bash
docker compose logs backend 2>&1 | head -50
# Check MongoDB connection, password encoding, etc.
```

**SSL errors:**
```bash
openssl x509 -in /etc/letsencrypt/live/zaply.in.net/fullchain.pem -text -noout | grep "Not After"
sudo certbot renew --force-renewal
```

**API returns 401:**
```bash
# Check SECRET_KEY matches
echo $SECRET_KEY | wc -c  # Should be > 32 chars

# Check auth header
curl -i -H "Authorization: Bearer YOUR_TOKEN" \
  https://zaply.in.net/api/v1/chats/
```

**MongoDB auth fails:**
```bash
docker compose logs mongodb | tail -30
# Check MONGO_PASSWORD is correct and URL-encoded
```

---

## Maintenance

```bash
# Pull updates
git pull origin main
docker compose up -d --build

# View logs
docker compose logs -f

# Backup MongoDB
docker compose exec -T mongodb mongodump \
  -u hypersend -p "$MONGO_PASSWORD" \
  --authenticationDatabase admin \
  -o /data/backup_$(date +%Y%m%d)
```

---

## Security Checklist

- [ ] **MONGO_PASSWORD** set to strong random value
- [ ] **SECRET_KEY** set to strong random value (> 32 chars)
- [ ] **DEBUG=False** in .env
- [ ] **CORS_ORIGINS** restricted to your domain
- [ ] DNS A record configured
- [ ] Let's Encrypt certs obtained
- [ ] Firewall allows only 22, 80, 443
- [ ] .env NOT committed to Git
- [ ] MongoDB backups scheduled
- [ ] Logs monitored regularly

---

**Last Updated:** December 22, 2025  
**Status:** Production Ready ✅  
**GitHub:** https://github.com/Mayankvlog/Hypersend
