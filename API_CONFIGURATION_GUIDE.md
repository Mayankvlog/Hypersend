# API Configuration Guide - Zaply Flutter Web App

## ✅ Current Configuration Status

All API endpoints are **correctly configured** for production deployment. Here's how it works:

---

## 1. API Base URL Configuration

### Location: `frontend/lib/core/constants/api_constants.dart`

```dart
class ApiConstants {
  // ✅ CORRECT: Full absolute URL including /api/v1
  static const String baseUrl = String.fromEnvironment(
    'API_BASE_URL',
    defaultValue: 'https://zaply.in.net/api/v1',
  );
  
  // Endpoint constants (used as relative paths)
  static const String authEndpoint = 'auth';
  static const String chatsEndpoint = 'chats';
  static const String messagesEndpoint = 'messages';
  static const String usersEndpoint = 'users';
  static const String filesEndpoint = 'files';
}
```

**Why this works:**
- `baseUrl` is the FULL production URL: `https://zaply.in.net/api/v1`
- This is set at Flutter build time via `--dart-define=API_BASE_URL=...`
- All relative paths are appended to this base URL

---

## 2. Dio HTTP Client Initialization

### Location: `frontend/lib/data/services/api_service.dart`

```dart
class ApiService {
  late final Dio _dio;

  ApiService() {
    _dio = Dio(
      BaseOptions(
        // ✅ CORRECT: Uses the full API base URL
        baseUrl: ApiConstants.baseUrl,  // = 'https://zaply.in.net/api/v1'
        connectTimeout: ApiConstants.connectTimeout,
        receiveTimeout: ApiConstants.receiveTimeout,
        contentType: 'application/json',
      ),
    );
    
    // Interceptors for auth, logging, error handling
    _dio.interceptors.add(LogInterceptor(...));
    _dio.interceptors.add(InterceptorsWrapper(...));
  }
}
```

---

## 3. API Method Example: Fetching Chats

### ✅ CORRECT Implementation

```dart
Future<List<Map<String, dynamic>>> getChats() async {
  try {
    // ✅ Use RELATIVE path - Dio will prepend baseUrl
    final response = await _dio.get('${ApiConstants.chatsEndpoint}/');
    // This becomes: GET https://zaply.in.net/api/v1/chats/
    
    return List<Map<String, dynamic>>.from(response.data['chats'] ?? const []);
  } catch (e) {
    rethrow;
  }
}
```

**How it works:**
1. `ApiConstants.chatsEndpoint` = `'chats'` (relative path)
2. `${ApiConstants.chatsEndpoint}/` = `'chats/'` (with trailing slash for FastAPI)
3. Dio combines: `baseUrl + 'chats/'`
4. **Final URL:** `https://zaply.in.net/api/v1/chats/`

---

## 4. All Endpoint Patterns

All 40+ endpoints follow this pattern with trailing slashes:

### Auth Endpoints
```dart
await _dio.post('${ApiConstants.authEndpoint}/register/');  // /api/v1/auth/register/
await _dio.post('${ApiConstants.authEndpoint}/login/');     // /api/v1/auth/login/
await _dio.post('${ApiConstants.authEndpoint}/logout/');    // /api/v1/auth/logout/
```

### User Endpoints
```dart
await _dio.get('${ApiConstants.usersEndpoint}/me/');        // /api/v1/users/me/
await _dio.put('${ApiConstants.usersEndpoint}/profile/');   // /api/v1/users/profile/
await _dio.get('${ApiConstants.usersEndpoint}/search/');    // /api/v1/users/search/
```

### Chat Endpoints
```dart
await _dio.get('${ApiConstants.chatsEndpoint}/');           // /api/v1/chats/
await _dio.post('${ApiConstants.chatsEndpoint}/$chatId/messages/');  // /api/v1/chats/{id}/messages/
```

### File Endpoints
```dart
await _dio.post('${ApiConstants.filesEndpoint}/init/');     // /api/v1/files/init/
await _dio.put('${ApiConstants.filesEndpoint}/$uploadId/chunk/');    // /api/v1/files/{id}/chunk/
```

---

## 5. Docker Build Configuration

### Location: `frontend/Dockerfile`

```dockerfile
# ✅ CORRECT: Pass API_BASE_URL at build time
RUN /opt/flutter/bin/flutter build web --release --no-tree-shake-icons \
    --dart-define=API_BASE_URL=https://zaply.in.net/api/v1
```

This ensures the compiled web app has the correct API base URL baked in.

---

## 6. Nginx Routing

### Location: `nginx.conf`

```nginx
location /api/ {
  # ✅ CORRECT: /api/* requests go to backend
  proxy_pass http://backend:8000;
  ...
}

location / {
  # ✅ CORRECT: /* requests go to frontend
  proxy_pass http://hypersend_frontend:80;
  ...
}
```

**Flow when user clicks "Load Chats":**
1. Browser makes request to: `https://zaply.in.net/api/v1/chats/`
2. Nginx sees `/api/` prefix → routes to backend (port 8000)
3. Backend processes the request → returns chat list
4. Browser shows "Chats loaded successfully ✅"

---

## 7. Request Flow Diagram

```
Flutter Frontend                Nginx Reverse Proxy            FastAPI Backend
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

User clicks "Load Chats"
       ↓
Dio.get('chats/')
       ↓
baseUrl = 'https://zaply.in.net/api/v1'
       ↓
Final URL = baseUrl + 'chats/' = 'https://zaply.in.net/api/v1/chats/'
       ↓
Browser XHR GET to zaply.in.net/api/v1/chats/
       ↓
                      Nginx sees /api/ prefix
                             ↓
                      Routes to backend:8000
                             ↓
                      Backend receives: /api/v1/chats/
                             ↓
                      FastAPI endpoint: @app.get('/api/v1/chats/')
                             ↓
                      Returns: {"chats": [...]}
       ↓
Browser displays chats list ✅
```

---

## 8. Why This Fix Works

### ❌ OLD (BROKEN):
```dart
baseUrl: '/api/v1/'  // Relative path
// Browser tries to resolve: https://zaply.in.net/api/v1/chats/
// But in browser context: https://zaply.in.net:443/api/v1/chats/
// Nginx doesn't find this exactly, routes to frontend
// → NS_ERROR_GENERATE_FAILURE ❌
```

### ✅ NEW (CORRECT):
```dart
baseUrl: 'https://zaply.in.net/api/v1'  // Absolute URL
// Browser makes: https://zaply.in.net/api/v1/chats/
// Nginx sees /api/ → routes to backend
// → 200 OK ✅
```

---

## 9. Testing the Fix

### On Your VPS:

```bash
# 1. Pull latest changes
cd /hypersend/Hypersend
git pull origin main

# 2. Rebuild Docker image (includes Flutter build with correct API_BASE_URL)
docker compose up -d --build

# 3. Check frontend is healthy
docker compose ps
# Should show: hypersend_frontend ... (healthy)

# 4. Check backend is healthy
docker compose ps
# Should show: hypersend_backend ... (healthy)

# 5. Test from browser
# Go to: https://zaply.in.net/#/chats
# Open DevTools → Network tab
# Should see: GET https://zaply.in.net/api/v1/chats/ → 200 OK
```

---

## 10. Adding New Endpoints

When adding a new API endpoint, follow this pattern:

```dart
// 1. Add constant to api_constants.dart
static const String newEndpoint = 'new-feature';

// 2. Add method to api_service.dart
Future<Map<String, dynamic>> getNewFeature() async {
  try {
    // Use relative path with trailing slash
    final response = await _dio.get('${ApiConstants.newEndpoint}/');
    // This becomes: GET https://zaply.in.net/api/v1/new-feature/
    return response.data;
  } catch (e) {
    rethrow;
  }
}

// 3. Use in your screen/service
final data = await serviceProvider.apiService.getNewFeature();
```

---

## Summary

✅ **Current Status:** All API endpoints are correctly configured
- BaseURL: `https://zaply.in.net/api/v1` (absolute URL)
- Endpoints: All use relative paths with trailing slashes
- Docker: Passes correct API_BASE_URL during build
- Nginx: Routes `/api/*` to backend, `/*` to frontend
- Expected: Browser requests → `https://zaply.in.net/api/v1/...` → 200 OK

🚀 **Ready for deployment!**
