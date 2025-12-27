# 🚀 Hypersend - Fast & Secure Messaging Platform



A modern, feature-rich messaging application built with Flutter and FastAPI, inspired by Telegram's functionality and design philosophy.

## 🎯 Quick Overview

**Hypersend** is a cross-platform messaging app with:
- ✅ Real-time chat with WebSocket support
- ✅ Secure P2P file transfer 
- ✅ Advanced contact management (Telegram-like)
- ✅ User authentication & permissions
- ✅ Full Docker containerization
- ✅ Production-ready Nginx reverse proxy
- ✅ Modern UI/UX inspired by Telegram

---

## 🌟 Features

### 📱 Core Messaging
- **Real-time Chat**: Instant messaging with delivery confirmation
- **File Sharing**: Secure file transfer with resumable uploads
- **Media Support**: Photos, videos, documents, and more
- **Voice Messages**: High-quality voice recording and playback
- **Message Reactions**: Express emotions with emoji reactions
- **Message Search**: Powerful search across all conversations

### 👥 Contact Management (NEW!)
- **Smart Contacts**: Auto-sync phone contacts with app users
- **Contact Search**: Find users by name, username, or phone number
- **Online Status**: Real-time online/offline indicators
- **Last Seen**: "Last seen 5 minutes ago" timestamps
- **Block/Unblock**: Privacy controls for unwanted contacts
- **Contact Organization**: Efficient contact management
- **Phone Integration**: Add contacts via phone number
- **Profile Views**: Detailed user information display

### 🔒 Security & Privacy
- **Transport Layer Security**: HTTPS/TLS encryption for all communications
- **Privacy Settings**: Granular privacy controls
- **Auto-Delete Messages**: Self-destructing messages
- **Content Privacy**: Sensitive content protection
- **Authentication**: Secure user authentication with JWT tokens

### 📁 File Management
- **Resumable Uploads**: Large file uploads with resume capability
- **Cloud Storage**: Secure cloud storage integration
- **File Manager**: Built-in file organization system
- **Quota Management**: Track storage usage and limits
- **File Preview**: Quick file preview without download

### 🎨 User Experience
- **Modern UI**: Clean, intuitive interface inspired by Telegram
- **Dark Theme**: Beautiful dark theme throughout app
- **Cross-Platform**: Works on iOS, Android, Web, Desktop
- **Offline Support**: Access messages and files offline
- **Push Notifications**: Real-time message alerts

---

## 🛠️ Technology Stack

### Frontend (Flutter)
- **Framework**: Flutter 3.35.6+
- **Navigation**: Go Router
- **HTTP Client**: Dio
- **State Management**: Provider/Service Pattern
- **File Handling**: File Picker
- **Models**: Equatable for value equality

### Backend (FastAPI)
- **Framework**: FastAPI 0.115.5+
- **Database**: MongoDB 7.0
- **Authentication**: JWT (HS256)
- **File Storage**: Chunked uploads
- **Real-time**: WebSocket support
- **Validation**: Pydantic models

### Infrastructure
- **Web Server**: Nginx (Alpine)
- **Containerization**: Docker & Docker Compose
- **Reverse Proxy**: Nginx with SSL termination
- **Database**: MongoDB with replica support
- **File Storage**: Local filesystem with quota management

---

## 📁 Project Structure

```
hypersend/
├── backend/                    # FastAPI backend
│   ├── main.py               # Application entry
│   ├── database.py           # MongoDB connection
│   ├── config.py             # Configuration & settings
│   ├── security.py           # JWT & authentication
│   ├── models.py             # Data models (enhanced with contact fields)
│   ├── routes/               # API endpoints
│   │   ├── auth.py          # Authentication endpoints
│   │   ├── chats.py         # Chat management
│   │   ├── users.py         # User management + contact features
│   │   ├── files.py         # File operations
│   │   ├── p2p_transfer.py  # P2P file transfer (WebSocket)
│   │   └── updates.py       # Real-time updates
│   ├── auth/                 # Auth utilities
│   ├── Dockerfile            # Backend container
│   └── requirements.txt       # Python dependencies
│
├── frontend/                   # Flutter app
│   ├── lib/                  # Flutter source code
│   │   ├── core/            # Core utilities and constants
│   │   │   ├── constants/    # App constants (API, strings, etc.)
│   │   │   ├── router/       # Navigation and routing
│   │   │   ├── theme/        # App theme and styling
│   │   │   └── utils/        # Helper utilities
│   │   ├── data/            # Data layer
│   │   │   ├── models/       # Data models (User, Chat, Message, etc.)
│   │   │   ├── mock/         # Mock data for development
│   │   │   └── services/     # API services and repositories
│   │   └── presentation/     # UI layer
│   │       ├── screens/       # Screen widgets (including Contacts)
│   │       └── widgets/      # Reusable UI components
│   ├── pubspec.yaml          # Flutter dependencies
│   ├── Dockerfile            # Frontend container (multi-stage build)
│   └── build/                # Compiled web/platform builds
│
├── scripts/                    # Utility scripts
│   └── seed_mongodb.py       # Database initialization
│
├── tests/                      # Test suite
│   └── test_backend.py       # Backend tests
│
├── docker-compose.yml        # Docker orchestration
├── nginx.conf                # Nginx configuration
├── assets/                   # App assets (icons, images)
└── README.md                 # Full documentation
```

---

## 🚀 Quick Start (Docker)

### Prerequisites
- Docker & Docker Compose installed
- Git
- `.env` file with required variables

### Step 1: Clone Repository

```bash
git clone https://github.com/Mayankvlog/Hypersend.git
cd Hypersend
```

### Step 2: Create `.env` File

```bash
cat > .env << EOF
MONGO_USER=hypersend
MONGO_PASSWORD=your_secure_password_here
SECRET_KEY=your_secret_key_here_min_32_chars
API_BASE_URL=https://zaply.in.net/api/v1
PRODUCTION_API_URL=https://zaply.in.net/api/v1
NGINX_PORT=8080
NGINX_PORT_SSL=8443
EOF
```

### Step 3: Start Services

```bash
# Build and start all services
docker compose up -d --build

# Check status
docker compose ps

# View logs
docker compose logs -f
```

### Step 4: Verify Services

- **Backend**: http://localhost:8000/health
- **Frontend**: http://localhost:8550 (Nginx hosted)
- **Nginx**: http://localhost:8080 (Reverse proxy)
- **MongoDB**: Internal network (27017)

---

## 🔧 Key Fixes Applied (December 2025)

### Issue: Frontend Container Crashing
**Problem**: Docker-compose was referencing a pre-built image `mayank035/hypersend-frontend:latest` which had incorrect startup command (`python app.py`), causing the container to crash.

**Solution**: Updated `docker-compose.yml` to **build the frontend locally** from the Dockerfile:

```yaml
# OLD (BROKEN)
frontend:
  image: mayank035/hypersend-frontend:latest
  # This image had wrong command and was restarting

# NEW (FIXED)
frontend:
  build:
    context: ./frontend
    dockerfile: Dockerfile
  # Now builds Flutter web app correctly with Nginx
```

**What This Fixes**:
- ✅ Frontend builds from local Flutter source
- ✅ Multi-stage build produces optimized web app
- ✅ Serves with Nginx on port 8550
- ✅ Proper health checks work
- ✅ No more container restarts

---

## 🌐 API Endpoints

### Authentication
```
POST   /auth/register          # Register new user
POST   /auth/login             # Login & get JWT token
POST   /auth/refresh           # Refresh expired token
POST   /auth/logout            # Logout
```

### Chats
```
GET    /chats/                 # List all chats
POST   /chats/                 # Create chat
GET    /chats/{chat_id}        # Get chat details
POST   /chats/{chat_id}/message # Send message
WS     /chats/{chat_id}/ws     # Real-time updates
```

### P2P File Transfer 
```
POST   /p2p/send               # Initiate transfer
WS     /p2p/sender/{session_id} # Sender stream
WS     /p2p/receiver/{session_id} # Receiver stream
GET    /p2p/status/{session_id}  # Transfer status
GET    /p2p/history/{chat_id}    # Transfer history
```

### User Management
```
GET    /users/me               # Current user profile
PUT    /users/profile          # Update profile
POST   /users/avatar           # Upload profile picture
GET    /users/search           # Search users by name/phone
```

### Contact Management (NEW!)
```
GET    /users/contacts/list           # Get user's contacts
POST   /users/contacts/add           # Add user to contacts
DELETE /users/contacts/{contact_id}  # Remove from contacts
POST   /users/contacts/sync          # Sync phone contacts
GET    /users/contacts/search         # Search for contacts
POST   /users/contacts/block/{user_id} # Block user
DELETE /users/contacts/block/{user_id} # Unblock user
```

---

## 📱 New Features (December 2025)

### 🎯 Telegram-like Contact System
We've just implemented a complete contact management system inspired by Telegram:

#### **Contact Management Endpoints**
- `GET /users/contacts/list` - Paginated contact list
- `POST /users/contacts/add` - Add user to contacts
- `DELETE /users/contacts/{id}` - Remove contact
- `POST /users/contacts/sync` - Sync phone contacts
- `GET /users/contacts/search` - Search with contact status

#### **Enhanced User Model**
- Added `last_seen`, `is_online`, `status`, `phone`, `bio`
- Added `contacts` and `blocked_users` arrays
- Added `contacts_count` for quick stats

#### **Frontend Contacts Screen**
- **3 Main Tabs**: All Contacts, Search, Sync
- **Real-time Search**: By name, username, phone
- **Contact Actions**: Message, block, profile view
- **Phone Sync**: Match contacts with app users
- **Online Indicators**: Real-time status display

#### **Navigation Integration**
- Added Contacts tab to bottom navigation
- Contacts option in main menu
- Full route integration with Go Router

---

## 📦 Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MONGO_USER` | `hypersend` | MongoDB username |
| `MONGO_PASSWORD` | - | MongoDB password (required) |
| `SECRET_KEY` | Generated | JWT secret (min 32 chars) |
| `API_BASE_URL` | `http://localhost:8000` | Backend URL |
| `MONGODB_URI` | Auto-generated | Full MongoDB connection string |
| `DEBUG` | `True` | Debug mode (set `False` in production) |
| `NGINX_PORT` | `8080` | HTTP port |
| `NGINX_PORT_SSL` | `8443` | HTTPS port |

---

## 🐳 Docker Commands

```bash
# Start services
docker compose up -d --build

# Stop services
docker compose down

# View logs
docker compose logs -f

# View specific service logs
docker compose logs -f backend
docker compose logs -f frontend
docker compose logs -f mongodb

# Access MongoDB
docker exec -it hypersend_mongodb mongosh -u hypersend -p <password>

# Rebuild a service
docker compose up -d --build backend

# Remove all containers and volumes
docker compose down -v
```

---

## 🔐 Security Features

- ✅ **JWT Authentication**: Secure token-based auth with HS256
- ✅ **HTTPS Ready**: Nginx with SSL certificate generation
- ✅ **Permission System**: Role-based access control
- ✅ **Secure File Transfer**: P2P without server storage
- ✅ **Password Hashing**: bcrypt hashing for passwords
- ✅ **CORS Protection**: Configurable CORS origins
- ✅ **Rate Limiting**: Per-user rate limits
- ✅ **Contact Privacy**: Secure contact sync with encryption
- ✅ **Blocking System**: User privacy controls
- ✅ **Profile Security**: Safe profile picture uploads

---

## ⚙️ Configuration Files

### Docker Compose (`docker-compose.yml`)
Orchestrates 4 services:
- **nginx**: Reverse proxy & SSL termination (port 8080/8443)
- **backend**: FastAPI application (port 8000)
- **frontend**: Flutter web app served by Nginx (port 8550)
- **mongodb**: MongoDB database (internal)

### Nginx (`nginx.conf`)
- Reverse proxy for backend & frontend
- SSL/TLS termination
- Caching and performance optimization
- Health check endpoints

### Backend (`backend/config.py`)
- Environment-based configuration
- Production/development modes
- JWT settings
- CORS configuration

---

## 🧪 Testing

### Run Backend Tests
```bash
# Run all tests
python -m pytest -v

# Run specific test file
python -m pytest tests/test_backend.py -v

# Run with coverage
python -m pytest --cov=backend tests/
```

### Current Test Status
✅ All tests passing (3/3)

---

## 📝 MongoDB Collections

The application automatically creates these collections:

```javascript
// Users collection
db.users.find({})

// Chats collection
db.chats.find({})

// Messages collection
db.messages.find({})

// Files metadata collection
db.files.find({})
```

### Create User Manually
```bash
docker exec -it hypersend_mongodb mongosh -u hypersend -p <password>

// In MongoDB shell:
use hypersend
db.users.insertOne({
  _id: ObjectId(),
  email: "user@example.com",
  username: "john_doe",
  password_hash: "$2b$12$...",
  created_at: new Date(),
  updated_at: new Date(),
  is_active: true
})
```

---

## 🚨 Troubleshooting

### Frontend Container Keeps Restarting
**Solution**: Ensure `docker-compose.yml` has the `build` section for frontend (not the old `image` reference). Run:
```bash
docker compose down -v
docker compose up -d --build
```

### MongoDB Connection Failed
```bash
# Check MongoDB is healthy
docker compose ps mongodb

# Check logs
docker compose logs mongodb

# Verify credentials in .env match docker-compose.yml
```

### Nginx SSL Certificate Issues
```bash
# Nginx will auto-generate self-signed certificate
# For production, use proper certificates with proper Certificate Authority

# To manually regenerate:
docker exec hypersend_nginx openssl req -x509 -nodes -days 365 \
  -newkey rsa:2048 -keyout /etc/nginx/ssl/key.pem \
  -out /etc/nginx/ssl/cert.pem -subj '/CN=zaply.in.net'
```

### Port Already in Use
```bash
# Change ports in docker-compose.yml or .env
# Example: NGINX_PORT=8081 (instead of 8080)
```

---

## 📚 Additional Resources

- **Full API Documentation**: See [README.md](README.md)
- **Nginx Setup Guide**: See [NGINX_QUICK_START.md](NGINX_QUICK_START.md)
- **Backend Config**: See [backend/config.py](backend/config.py)
- **Flutter App**: See [frontend/README.md](frontend/README.md)

---

## 🧪 Testing

### Backend Tests
```bash
cd backend
python -m pytest -v
```

### Frontend Tests
```bash
cd frontend
flutter test
```

### Integration Tests
```bash
flutter test integration_test/
```

### Current Test Status
✅ All backend tests passing (3/3)
✅ All frontend tests passing
✅ Contact management features tested

---

## 🚀 Deployment

### Production Deployment with Docker
1. Configure environment variables
2. Build and deploy
```bash
docker-compose -f docker-compose.prod.yml up -d
```

### Manual Deployment
1. Set up reverse proxy (Nginx)
2. Configure SSL certificates
3. Deploy backend application
4. Build and serve frontend files
5. Configure MongoDB replica set

---

## 📊 Project Statistics

- **Backend Endpoints**: 25+ API endpoints
- **Frontend Screens**: 15+ screens
- **Contact Features**: 8 major contact management features
- **File Upload**: Chunked uploads with resume support
- **Security**: JWT auth + encryption + blocking
- **Platform Support**: iOS, Android, Web, Desktop

---

## 🗺️ Roadmap

### v1.1.0 (Q1 2025)
- [ ] Voice and video calls
- [ ] Message scheduling
- [ ] Advanced file compression
- [ ] Multi-device synchronization

### v1.2.0 (Q2 2025)
- [ ] End-to-end encrypted backup
- [ ] Bot platform support
- [ ] Channels and broadcasts
- [ ] Advanced privacy settings

### v2.0.0 (H2 2025)
- [ ] Decentralized architecture
- [ ] Blockchain-based identity
- [ ] Advanced AI features
- [ ] Cross-platform desktop app

