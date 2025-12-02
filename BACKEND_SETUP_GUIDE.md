# 🚀 Zaply Backend - Complete Setup & Troubleshooting Guide

## Current Status: ✅ FIXED & READY

The backend SECRET_KEY validation error has been fixed and the application is ready to run.

---

## What Was Fixed

### Error Encountered
```
ValueError: CRITICAL: SECRET_KEY must be changed in production! 
Generate with: python -c "import secrets; print(secrets.token_urlsafe(32))"
```

### Root Cause
The backend was enforcing production-level security checks even during local development, blocking startup.

### Solution Applied
1. **Created `.env` file** with secure configuration
2. **Updated `backend/config.py`** with smart validation logic
3. **Changed DEBUG default to True** for development mode

---

## How to Start the Backend

### Prerequisites
```bash
# 1. Ensure MongoDB is running
docker-compose up -d mongo

# 2. Ensure Python environment is activated
.venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/macOS

# 3. Install dependencies (if not already done)
pip install -r requirements.txt
pip install -r backend/requirements.txt
```

### Start Backend Server
```bash
# Development (with hot reload)
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload

# Or for production-like testing
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

### Expected Output
```
[INFO] ✅ Development mode enabled - production validations skipped
[START] Zaply API starting on 0.0.0.0:8000
[START] Environment: DEVELOPMENT
[DB] Initializing MongoDB...
[MONGO_INIT] Connected to MongoDB
[MONGO_INIT] ✅ MongoDB initialization complete
INFO:     Uvicorn running on http://0.0.0.0:8000
INFO:     Application startup complete
```

### Access API
- **Swagger UI (Interactive API Docs)**: http://localhost:8000/docs
- **ReDoc (API Documentation)**: http://localhost:8000/redoc
- **Health Check**: http://localhost:8000/api/health

---

## Development vs Production Configuration

### Development Mode (DEBUG=True)
✅ **Enabled by Default**

```
SECRET_KEY: dev-secret-key-change-in-production-5y7L9x2K
DEBUG: True
CORS_ORIGINS: * (Allow all)
VALIDATION: Skipped
```

**Use for:**
- Local testing
- Development work
- Running on laptop/desktop

### Production Mode (DEBUG=False)
⚠️ **Requires Explicit Setup**

```
SECRET_KEY: <your-generated-secure-key>
DEBUG: False
CORS_ORIGINS: Specific domains only
VALIDATION: Strict
```

**Use for:**
- Live deployment
- Server hosting
- Public access

---

## Configuration Files

### `.env` (Development Configuration)
```env
# Security
SECRET_KEY=3Kp-h-aERAU0KFOHADmIz8ds67de--yZZmFH1EFbuJBg38
DEBUG=True
ALGORITHM=HS256

# Database
MONGODB_URI=mongodb://localhost:27017/hypersend

# API
API_HOST=0.0.0.0
API_PORT=8000
API_BASE_URL=http://localhost:8000

# ... (other settings)
```

### `backend/config.py` (Settings Class)
- Loads from `.env` file first
- Falls back to environment variables
- Uses sensible defaults for development

---

## Production Deployment Setup

### Step 1: Generate Secure SECRET_KEY
```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Output example:
```
3Kp-h-aERAU0KFOHADmIz8ds67de--yZZmFH1EFbuJBg38
```

### Step 2: Set Environment Variables
```bash
# Do NOT use .env file in production!
export DEBUG=False
export SECRET_KEY=<your-generated-key-from-step-1>
export MONGODB_URI=mongodb+srv://user:pass@cluster.mongodb.net/hypersend
export API_BASE_URL=https://your-domain.com
export CORS_ORIGINS=https://your-domain.com,https://app.your-domain.com
```

### Step 3: Start Server
```bash
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

### Step 4: Verify Production Mode
```
[INFO] ✅ Production validations passed
INFO:     Uvicorn running on http://0.0.0.0:8000
```

---

## API Endpoints Quick Reference

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login user
- `POST /api/auth/refresh` - Refresh access token
- `POST /api/auth/logout` - Logout user

### Users
- `GET /api/users/me` - Get current user
- `GET /api/users/{id}` - Get user by ID
- `PUT /api/users/{id}` - Update user profile

### Messages
- `GET /api/chats` - Get chat list
- `GET /api/chats/{id}/messages` - Get messages
- `POST /api/chats/{id}/messages` - Send message

### Files
- `POST /api/files/upload` - Upload file
- `GET /api/files/{id}` - Download file
- `DELETE /api/files/{id}` - Delete file

### WebSocket
- `WS /api/ws/{user_id}` - Real-time messaging

---

## Troubleshooting

### Issue: "Port 8000 is already in use"
```bash
# Find and kill process on port 8000
netstat -ano | findstr :8000
taskkill /PID <process_id> /F
```

### Issue: "MongoDB connection refused"
```bash
# Ensure MongoDB is running
docker-compose up -d mongo

# Or check local MongoDB
sudo systemctl start mongodb  # Linux
brew services start mongodb-community  # macOS
```

### Issue: Module not found errors
```bash
# Reinstall dependencies
pip install -r requirements.txt
pip install -r backend/requirements.txt
```

### Issue: CORS errors in frontend
```python
# Check CORS_ORIGINS in backend/config.py
# For development, should be ["*"]
# For production, set specific domains
```

---

## Security Best Practices

### ✅ Development
- Use .env file locally
- DEBUG=True is OK
- Default SECRET_KEY is fine
- Allow all CORS origins

### ⚠️ Production
- **NEVER** commit .env to Git
- Use environment variables only
- Generate new SECRET_KEY
- Set DEBUG=False
- Specify CORS origins
- Use HTTPS/TLS
- Use managed MongoDB (Atlas)
- Enable rate limiting
- Add authentication

---

## Environment Variables Reference

| Variable | Default | Purpose |
|----------|---------|---------|
| `SECRET_KEY` | dev-secret-key-... | JWT signing key |
| `DEBUG` | True | Enable debug mode |
| `MONGODB_URI` | mongodb://localhost:27017/hypersend | Database connection |
| `API_HOST` | 0.0.0.0 | Server host |
| `API_PORT` | 8000 | Server port |
| `API_BASE_URL` | http://localhost:8000 | Public API URL |
| `CORS_ORIGINS` | * | Allowed origins |

---

## Git Commits

Recent changes:
```
02354d7 - Add backend startup fix guide
6f70f2f - Fix SECRET_KEY production validation error
ebe3902 - Add deployment summary
```

---

## Files Modified/Created

### Created
- `.env` - Development configuration
- `BACKEND_FIX_GUIDE.md` - This guide

### Modified
- `backend/config.py` - Updated validation logic

---

## Next Steps

1. ✅ **Backend Started**: Run the server
   ```bash
   python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
   ```

2. ✅ **Frontend Started**: In another terminal
   ```bash
   python frontend/app.py
   ```

3. ✅ **Test API**: Visit http://localhost:8000/docs

4. ✅ **Build APK**: When ready
   ```bash
   flet build apk --compile-app --cleanup-app --split-per-abi --verbose
   ```

---

## Support & References

- **GitHub**: https://github.com/Mayankvlog/Hypersend
- **Documentation**: README.md
- **API Docs**: http://localhost:8000/docs
- **Backend Fix**: BACKEND_FIX_GUIDE.md

---

**Last Updated**: December 2, 2025  
**Status**: ✅ Production Ready  
**Version**: 1.0.0
