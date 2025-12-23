# 🛠️ Troubleshooting Guide - Zaply

## 🚨 Common Errors & Solutions

### 1. **"Cannot connect to server" Error**

**Problem:** `DioException [connection error]: The connection errored`

This means the **frontend cannot reach the backend server**.

**Solutions:**

#### Option A: Start Backend Locally (For Development)
```bash
# 1. Navigate to backend directory
cd backend

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Start MongoDB (if using Docker)
docker-compose up -d mongodb

# 4. Run FastAPI server
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

**Expected Output:**
```
[START] Zaply API running in DEBUG mode on 0.0.0.0:8000
[DB] Database connection established
[CORS] Allowing all origins (DEBUG mode)
```

#### Option B: Update Frontend API URL (For Development)
```bash
# Build Flutter app with local backend
cd frontend
flutter run --dart-define=API_BASE_URL=http://localhost:8000/api/v1/
```

#### Option C: Check Production Server
```bash
# Verify server is running
curl -v https://zaply.in.net/api/v1/health

# Should return: 200 OK
```

---

### 2. **"Invalid email or password" - But Credentials Are Correct**

**Problem:** Login fails even with correct credentials

**Solutions:**
- ✅ Ensure email is registered first (Register tab)
- ✅ Check capslock is off
- ✅ Verify email format is correct (user@example.com)
- ✅ Clear app cache: Settings → Apps → Zaply → Clear Cache

---

### 3. **"Email already registered" - But You're Trying to Login**

**Problem:** You see this error on login screen

**Solution:** 
- You're on the Register tab, not Login tab
- Click "I already have an account" to switch to Login
- Or tap the toggle button to switch forms

---

### 4. **"Request timeout" Error**

**Problem:** `Connection timeout` or `Receive timeout`

**Solutions:**
1. **Check internet connection**
   ```bash
   # Verify connectivity
   ping google.com
   ```

2. **Increase timeout values** (if network is slow):
   - Edit: `frontend/lib/core/constants/api_constants.dart`
   - Change: `connectTimeout: Duration(seconds: 60)`

3. **Check backend is responsive**
   ```bash
   curl -v https://zaply.in.net/api/v1/health
   ```

---

### 5. **Profile Update Returns 422 Error**

**Problem:** "Invalid data format" when updating profile

**Solutions:**
- ✅ Name must be at least 2 characters
- ✅ Email must be valid format (user@example.com)
- ✅ Username cannot be empty
- ✅ If changing email, make sure it's not already in use
- ✅ Check server logs: `docker logs hypersend_backend`

---

### 6. **MongoDB Connection Failed**

**Problem:** `[ERROR] Database connection failed`

**Solutions:**

If using Docker:
```bash
# Start MongoDB container
docker-compose up -d mongodb

# Check status
docker ps | grep mongodb

# View logs
docker logs hypersend_mongodb
```

If using local MongoDB:
```bash
# Start MongoDB service
# Windows: Open Services, find MongoDB, click Start
# Linux: sudo systemctl start mongod
# Mac: brew services start mongodb-community
```

If custom connection string, check `.env`:
```bash
MONGODB_URI=mongodb://user:pass@host:27017/hypersend
```

---

### 7. **"No issues found" in Flutter but App Won't Build**

**Problem:** `flutter analyze` is clean but build fails

**Solutions:**
```bash
# Clean everything
flutter clean

# Get fresh dependencies
flutter pub get

# Try building again
flutter run

# Or build APK
flutter build apk
```

---

### 8. **CORS Errors in Browser Console**

**Problem:** `Access to XMLHttpRequest at 'https://zaply.in.net/api/v1/...' from origin 'https://your-domain.com' has been blocked by CORS policy`

**Solutions:**
- Backend CORS already allows common origins
- If using custom domain, add it to `backend/config.py`:
  ```python
  "https://your-domain.com",
  ```

---

## 📋 Diagnostic Checklist

Use this to debug issues:

- [ ] **Backend Running?**
  ```bash
  curl https://zaply.in.net/api/v1/health
  ```

- [ ] **MongoDB Connected?**
  ```bash
  # Check logs
  docker logs hypersend_mongodb
  ```

- [ ] **Network Working?**
  ```bash
  ping google.com
  ```

- [ ] **Correct API URL in Flutter?**
  ```
  lib/core/constants/api_constants.dart → ApiConstants.baseUrl
  ```

- [ ] **Valid Credentials?**
  - Email format correct?
  - Not duplicate email on register?
  - Correct password on login?

- [ ] **Server Logs Show Errors?**
  ```bash
  docker logs hypersend_backend
  ```

---

## 🔍 Enabling Debug Logs

### Backend Logs
```bash
# All verbose logs
docker logs -f hypersend_backend

# Only errors
docker logs hypersend_backend 2>&1 | grep ERROR
```

### Frontend Logs
- Open DevTools in browser (F12)
- Go to Console tab
- Look for `[API_*]` messages
- Or in Terminal: `flutter run -v`

---

## 📞 Support Resources

- **Backend Status:** https://zaply.in.net/api/v1/health
- **API Docs:** https://zaply.in.net/api/v1/docs
- **GitHub:** https://github.com/Mayankvlog/Hypersend
- **Issues:** Open a GitHub issue with error message

---

## ✅ Quick Health Check

Run this to verify everything:

```bash
# 1. Backend responds
curl -s https://zaply.in.net/api/v1/health && echo "✅ Backend OK"

# 2. MongoDB works  
docker exec hypersend_mongodb mongosh --eval "db.adminCommand('ping')" && echo "✅ MongoDB OK"

# 3. Flutter compiles
cd frontend && flutter analyze && echo "✅ Flutter OK"

# 4. Tests pass
cd .. && pytest tests/ -v && echo "✅ Tests OK"
```

All should show ✅ for a working system!
