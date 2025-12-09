# HyperSend - Setup and Testing Guide

## 📋 Project Overview

**HyperSend** is a premium Telegram-style messaging application combining:
- **Frontend**: Flet framework (Python) - Cross-platform mobile/desktop UI
- **Backend**: FastAPI - RESTful API server
- **Database**: MongoDB - Document storage

---

## ✅ Setup Instructions

### 1. Environment Setup

#### Prerequisites
- Python 3.11+
- MongoDB 6.0+ (local or Docker)
- pip package manager

#### Backend Setup
```bash
# Install backend dependencies
pip install -r backend/requirements.txt

# Configure environment variables in .env
# Ensure SECRET_KEY is set (min 32 characters):
SECRET_KEY=your-super-secret-key-for-development-change-in-production-32-chars-min-8f7g9h2k3l4m5n6p
MONGODB_URI=mongodb://hypersend:Mayank@#03@localhost:27017/hypersend?authSource=admin&retryWrites=true
DEBUG=True
API_BASE_URL=http://localhost:8000
```

#### Frontend Setup
```bash
# Install frontend dependencies
pip install -r frontend/requirements.txt

# Frontend will use the API_BASE_URL from .env
# Update .env API_BASE_URL to match your backend URL
```

### 2. Start Services

#### Start Backend
```bash
# Development mode (with auto-reload)
python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

# Or directly
python backend/main.py
```

#### Start Frontend
```bash
python frontend/app.py
```

---

## 🧪 Testing Guide

### Backend API Testing

#### 1. Health Check
```bash
curl http://localhost:8000/health
# Expected: {"status": "healthy"}
```

#### 2. User Registration
```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test User",
    "email": "test@example.com",
    "password": "SecurePass123!"
  }'
```

#### 3. User Login
```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass123!"
  }'
# Returns: {"access_token": "...", "refresh_token": "...", "token_type": "bearer"}
```

#### 4. Create Private Chat
```bash
# Use the access_token from login response
curl -X POST http://localhost:8000/api/v1/chats/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -d '{
    "name": null,
    "member_ids": ["other_user_id"],
    "type": "private"
  }'
```

#### 5. Create Group Chat
```bash
curl -X POST http://localhost:8000/api/v1/chats/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -d '{
    "name": "My Group",
    "member_ids": ["user2_id", "user3_id"],
    "type": "group"
  }'
```

#### 6. Create Channel
```bash
curl -X POST http://localhost:8000/api/v1/chats/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -d '{
    "name": "My Channel",
    "member_ids": [],
    "type": "channel"
  }'
```

#### 7. List Chats
```bash
curl http://localhost:8000/api/v1/chats/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

#### 8. Send Message
```bash
curl -X POST http://localhost:8000/api/v1/chats/{chat_id}/messages \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -d '{
    "text": "Hello, World!"
  }'
```

---

## 🎯 Frontend Testing

### User Flow Testing

#### 1. Login
- Open app: `python frontend/app.py`
- Enter email and password from backend test user
- Verify session is saved
- Check settings page loads without errors

#### 2. Chat Creation
- Click "New Chat" button
- Enter recipient email/username
- Verify private chat is created
- Send a test message

#### 3. Group/Channel Creation
- Click "New Group" or "New Channel"
- Enter group/channel name
- Add members (for groups)
- Verify chat appears in chat list with correct icon

#### 4. Settings Page
- Click Settings
- Verify no "Text margin" or icon errors
- Test theme switching
- Check language selection

#### 5. File Upload
- Click attachment button
- Select a file
- Verify chunked upload works
- Check file appears in chat

---

## 🐛 Common Issues & Solutions

### Issue 1: "module 'flet' has no attribute 'icons'"
**Status**: ✅ FIXED
- **Cause**: Incorrect icon reference (lowercase instead of uppercase)
- **Solution**: Use `ft.Icons` and `ft.Colors` (capitalized)
- **Commit**: c74354c

### Issue 2: "Text.__init__() got an unexpected keyword argument 'margin'"
**Status**: ✅ FIXED
- **Cause**: Text control doesn't support margin parameter
- **Solution**: Wrap Text in Container
- **Commit**: 3e32946

### Issue 3: "Group/Channel creation returns 403 Forbidden"
**Status**: ✅ FIXED
- **Cause**: Backend didn't validate group/channel types
- **Solution**: Added validation for all chat types in create_chat route
- **Commit**: f02975d

### Issue 4: "SECRET_KEY validation fails"
**Status**: ✅ FIXED
- **Cause**: Missing or too short SECRET_KEY in .env
- **Solution**: Add 32+ character SECRET_KEY to .env

### Issue 5: "Channels not displaying in chat list"
**Status**: ✅ FIXED
- **Cause**: Avatar logic didn't handle channel type
- **Solution**: Added channel icon support (CAMPAIGN icon)
- **Commit**: 90afd50

---

## 📊 Database Schema

### Collections

#### users
```json
{
  "_id": "ObjectId",
  "name": "string",
  "email": "string",
  "password_hash": "string",
  "quota_used": "number",
  "quota_limit": "number",
  "created_at": "datetime"
}
```

#### chats
```json
{
  "_id": "ObjectId",
  "type": "private|group|channel|saved",
  "name": "string",
  "members": ["user_id"],
  "created_at": "datetime"
}
```

#### messages
```json
{
  "_id": "ObjectId",
  "chat_id": "string",
  "sender_id": "string",
  "text": "string",
  "type": "text|file",
  "created_at": "datetime",
  "saved_by": ["user_id"]
}
```

#### files
```json
{
  "_id": "ObjectId",
  "upload_id": "string",
  "owner_id": "string",
  "filename": "string",
  "size": "number",
  "mime": "string",
  "checksum": "string",
  "status": "pending|completed|failed",
  "created_at": "datetime"
}
```

---

## 🚀 Running Tests

### Backend Tests
```bash
# Run all backend tests
python -m pytest tests/test_backend.py -v

# Run specific test
python -m pytest tests/test_backend.py::test_read_root -v
```

**Current Test Status**: ✅ All 3 tests passing
- ✅ test_read_root
- ✅ test_health_check  
- ✅ test_favicon

---

## 📦 Deployment Checklist

- [ ] Update SECRET_KEY to production value (32+ chars)
- [ ] Set DEBUG=False
- [ ] Update API_BASE_URL to production domain
- [ ] Update CORS_ORIGINS to production domains
- [ ] Use managed MongoDB instance (MongoDB Atlas)
- [ ] Enable HTTPS/SSL
- [ ] Configure email SMTP (for password reset)
- [ ] Set up WebSocket for real-time messaging
- [ ] Configure push notifications
- [ ] Run security audit

---

## 📝 Recent Commits

| Commit | Message | Status |
|--------|---------|--------|
| f02975d | fix: enable group and channel chat creation | ✅ DONE |
| c74354c | fix: ensure consistent ft.Icons usage | ✅ DONE |
| 90afd50 | fix: add channel icon support | ✅ DONE |
| 3e32946 | fix: resolve Text margin errors | ✅ DONE |
| f04cbd4 | fix: Pydantic V2 migration + tests | ✅ DONE |

---

## 🔗 API Endpoints

### Authentication
- `POST /api/v1/auth/register` - Register new user
- `POST /api/v1/auth/login` - Login user
- `POST /api/v1/auth/refresh` - Refresh access token

### Chats
- `POST /api/v1/chats/` - Create chat
- `GET /api/v1/chats/` - List chats
- `GET /api/v1/chats/{chat_id}` - Get chat details
- `GET /api/v1/chats/{chat_id}/messages` - Get messages
- `POST /api/v1/chats/{chat_id}/messages` - Send message

### Files
- `POST /api/v1/files/init` - Initialize file upload
- `POST /api/v1/files/upload/{upload_id}` - Upload file chunk
- `POST /api/v1/files/complete/{upload_id}` - Complete upload
- `GET /api/v1/files/{file_id}` - Download file

### Users
- `GET /api/v1/users/me` - Get current user
- `PUT /api/v1/users/me` - Update profile
- `GET /api/v1/users/search` - Search users

---

## 📞 Support

For issues or questions:
1. Check this guide first
2. Review recent commits
3. Check backend logs
4. Enable DEBUG=True for detailed logging
5. Check database connection

---

**Last Updated**: December 9, 2025
**Status**: ✅ All Critical Issues Fixed & Tested
