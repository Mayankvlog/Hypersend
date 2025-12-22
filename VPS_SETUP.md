# VPS MongoDB Credentials Setup - Quick Start Guide

## Problem Fixed ✅

The backend was failing with:
```
pymongo.errors.InvalidURI: Username and password must be escaped according to RFC 3986
```

## Root Cause

MongoDB credentials with special characters (e.g., `Pass@#$123`) were being passed directly without URL encoding.

## Solution Implemented

1. **Backend now auto-encodes**: `backend/config.py` uses `urllib.parse.quote_plus()` to handle URL encoding automatically
2. **Cleaner config**: Pass raw credentials in `.env` file, backend handles encoding
3. **docker-compose updated**: Passes individual credential components instead of pre-constructed URI

---

## Setup Instructions for Your VPS

### Step 1: Pull Latest Code

```bash
cd /hypersend/Hypersend
git pull origin main
```

### Step 2: Create/Update `.env` File

Get your `MONGO_PASSWORD` from GitHub Secrets, then create `.env`:

```bash
cat > .env << 'EOF'
# ===== SECURITY =====
SECRET_KEY=your-super-secret-key-for-development-change-in-production-32-chars-min
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=30

# ===== MONGODB CREDENTIALS =====
# Use RAW password from GitHub Secrets (no URL encoding needed)
MONGO_USER=hypersend
MONGO_PASSWORD=<PASTE_YOUR_ACTUAL_PASSWORD_HERE>
MONGO_HOST=mongodb
MONGO_PORT=27017
MONGO_INITDB_DATABASE=hypersend

# ===== API CONFIGURATION =====
API_HOST=0.0.0.0
API_PORT=8000
API_BASE_URL=https://zaply.in.net/api/v1
DEBUG=False

# ===== FILE STORAGE =====
STORAGE_MODE=local
DATA_ROOT=/data
CHUNK_SIZE=4194304
MAX_FILE_SIZE_BYTES=42949672960
MAX_PARALLEL_CHUNKS=4
FILE_RETENTION_HOURS=0
UPLOAD_EXPIRE_HOURS=24

# ===== RATE LIMITING =====
RATE_LIMIT_PER_USER=100
RATE_LIMIT_WINDOW_SECONDS=60

# ===== EMAIL / SMTP (Optional) =====
SMTP_HOST=
SMTP_PORT=587
SMTP_USERNAME=
SMTP_PASSWORD=
SMTP_USE_TLS=True
EMAIL_FROM=
EOF
```

**Replace `<PASTE_YOUR_ACTUAL_PASSWORD_HERE>` with your actual MongoDB password from GitHub Secrets.**

### Step 3: Rebuild and Start Containers

```bash
# Remove old containers
docker compose down

# Optional: Remove old MongoDB data (only if you want to reset)
# docker volume rm hypersend_mongodb_data

# Start with new .env
docker compose up -d --build

# Wait 30 seconds for MongoDB to initialize
sleep 30

# Check status
docker compose ps
```

### Step 4: Verify Success

Expected output from `docker compose ps`:
```
NAME                IMAGE               STATUS
hypersend_nginx     nginx:alpine        Up (healthy)
hypersend_mongodb   mongo:7.0           Up (healthy)
hypersend_backend   hypersend-backend   Up (healthy)
hypersend_frontend  hypersend-frontend  Up (healthy)
```

Check backend logs:
```bash
docker compose logs backend --tail 20
```

You should see:
```
[OK] Connected to MongoDB: hypersend
[START] Zaply API starting on 0.0.0.0:8000
```

---

## How It Works Now

### Backend Config (`backend/config.py`)

```python
from urllib.parse import quote_plus

_MONGO_USER = os.getenv("MONGO_USER", "hypersend")
_MONGO_PASSWORD = os.getenv("MONGO_PASSWORD", "hypersend_secure_password")

# Automatically URL-encode special characters
MONGODB_URI = f"mongodb://{quote_plus(_MONGO_USER)}:{quote_plus(_MONGO_PASSWORD)}@mongodb:27017/hypersend?authSource=admin&retryWrites=true"
```

### docker-compose.yml

```yaml
backend:
  environment:
    MONGO_USER: ${MONGO_USER:-hypersend}
    MONGO_PASSWORD: ${MONGO_PASSWORD:-hypersend_secure_password}
    MONGO_HOST: ${MONGO_HOST:-mongodb}
    MONGO_PORT: ${MONGO_PORT:-27017}
    MONGO_INITDB_DATABASE: ${MONGO_INITDB_DATABASE:-hypersend}
```

### .env File

```
MONGO_USER=hypersend
MONGO_PASSWORD=your_actual_password_from_github_secrets
MONGO_HOST=mongodb
MONGO_PORT=27017
MONGO_INITDB_DATABASE=hypersend
```

**No URL encoding needed in `.env` - backend handles it automatically!**

---

## Troubleshooting

### Still getting "InvalidURI" error?

1. Verify `.env` file exists: `cat .env | grep MONGO_PASSWORD`
2. Check password has no URL encoding: Should be `Pass@#$123`, NOT `Pass%40%23%24123`
3. Rebuild containers: `docker compose down && docker compose up -d --build`

### MongoDB won't start?

```bash
docker compose logs mongodb --tail 30
```

Look for credentials mismatch errors.

### Backend can't connect to MongoDB?

```bash
docker compose logs backend --tail 50
```

If you see "Authentication failed" (not "InvalidURI"), your MONGO_PASSWORD is wrong. Update `.env` and rebuild.

---

## Next Steps

- The GitHub Actions workflow automatically deploys the latest code
- For any future changes, just update `.env` with new credentials if needed
- Keep `.env` in `.gitignore` (already configured) to prevent leaking secrets

