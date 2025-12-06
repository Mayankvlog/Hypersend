# 🚀 Zaply - Real-Time Messaging & P2P File Transfer

A modern, cross-platform messaging application built with **Flet** (Flutter for Python) and **FastAPI**, featuring real-time chat, secure P2P file transfer, and advanced permissions management.

![Status](https://img.shields.io/badge/status-production--ready-brightgreen)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Flet](https://img.shields.io/badge/flet-0.28.3-orange)
![FastAPI](https://img.shields.io/badge/fastapi-latest-green)
![License](https://img.shields.io/badge/license-MIT-blue)

---

## 📋 Table of Contents

- [Features](#features)
- [Tech Stack](#tech-stack)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Project Structure](#project-structure)
- [Configuration](#configuration)
- [Building APK](#building-apk)
- [Deployment](#deployment)
- [API Documentation](#api-documentation)
- [Contributing](#contributing)
- [License](#license)

---

## ✨ Features

### Core Messaging
- 💬 **Real-time Chat** - Instant messaging with WebSocket support
- 👥 **User Profiles** - Complete user management system
- 🔐 **Secure Authentication** - JWT-based auth with refresh tokens
- 📱 **Cross-platform** - Works on Android, iOS, Windows, macOS, Linux, and Web

### P2P Features
- 📤 **Peer-to-Peer File Transfer** - Direct device-to-device file sharing
- 🔒 **Encrypted Connections** - Secure transfer protocols
- 📊 **Transfer Management** - Track and manage active transfers

### Permissions & Privacy
- 🛡️ **Permission System** - Telegram-style permissions for:
  - 📍 Location access
  - 📷 Camera
  - 🎤 Microphone
  - 👥 Contacts
  - ☎️ Phone
  - 💾 Storage
- ✅ **Fine-grained Controls** - Per-permission allow/disallow settings
- 🔔 **Permission Requests** - User-friendly permission flows

### Data Management
- 💾 **MongoDB Integration** - Scalable document database
- 📁 **File Storage** - Organized file management system
- 🗑️ **Temp Directory** - Automatic cleanup of temporary files

---

## 🛠️ Tech Stack

### Frontend
- **Flet 0.28.3** - UI framework (Flutter for Python)
- **Python 3.11+** - Application logic
- **RESTful API Client** - HTTP communication

### Backend
- **FastAPI** - Modern async web framework
- **Motor** - Async MongoDB driver
- **MongoDB 7.0** - NoSQL database
- **Uvicorn** - ASGI server

### DevOps & Build
- **Docker** - Containerization
- **Docker Compose** - Multi-container orchestration
- **Nginx** - Reverse proxy
- **Gradle** - Android build system
- **Flutter** - Cross-platform compilation

---

## 📦 Prerequisites

### System Requirements
- **Python**: 3.11 or higher
- **Java**: JDK 11+ (for Android builds)
- **Android SDK**: API 31+ (for APK builds)
- **Flutter SDK**: Latest stable (for Android builds)
- **MongoDB**: 7.0+ (local or Docker)

### Development Tools
```bash
# Python packages (auto-installed)
- flet==0.28.3
- fastapi==latest
- motor==latest
- uvicorn==latest
- httpx==latest

# System tools
- Git
- Docker (optional, for deployment)
- adb (Android Debug Bridge)
```

---

## 🚀 Installation

### 1. Clone Repository
```bash
git clone https://github.com/Mayankvlog/Hypersend.git
cd Hypersend
```

### 2. Create Virtual Environment
```bash
# Windows
python -m venv .venv
.venv\Scripts\activate.ps1

# Linux/macOS
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Setup Backend
```bash
cd backend
pip install -r requirements.txt
cd ..
```

### 5. Setup Frontend
```bash
cd frontend
pip install -r requirements.txt
cd ..
```

### 6. Configure MongoDB
```bash
# Using Docker (on your VPS 139.59.82.105)
docker run -d \
  -p 27017:27017 \
  -v mongodb_data:/data/db \
  --name zaply_mongo \
  mongo:7.0

# OR using MongoDB directly on the VPS
# Ensure MongoDB is running and accessible at 139.59.82.105:27017
```

### 7. Start Backend Server
```bash
cd backend
python main.py
# Server runs at http://139.59.82.105:8000  (your DigitalOcean VPS)
# API docs at http://139.59.82.105:8000/docs
```

### 8. Start Frontend App
```bash
cd frontend
python app.py
# App launches in native window
```

---

## ⚡ Quick Start

### Development Setup (All-in-One)
```bash
# 1. Clone & setup
git clone https://github.com/Mayankvlog/Hypersend.git
cd Hypersend
python -m venv venv
source venv/bin/activate  # On Windows: .venv\Scripts\activate.ps1

# 2. Install all dependencies
pip install -r requirements.txt
cd backend && pip install -r requirements.txt && cd ..
cd frontend && pip install -r requirements.txt && cd ..

# 3. Start MongoDB (Docker)
docker-compose up -d mongodb

# 4. In separate terminals:
# Terminal 1: Backend
cd backend && python main.py

# Terminal 2: Frontend
cd frontend && python app.py
```

### Docker Deployment
```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

---

## 📂 Project Structure

```
Zaply/
├── backend/                    # FastAPI backend
│   ├── main.py                # Server entry point
│   ├── models.py              # Database models
│   ├── database.py            # MongoDB connection
│   ├── config.py              # Configuration
│   ├── auth/                  # Authentication
│   │   ├── utils.py           # JWT utilities
│   │   └── __init__.py
│   ├── routes/                # API endpoints
│   │   ├── auth.py            # Authentication endpoints
│   │   ├── users.py           # User management
│   │   ├── chats.py           # Chat endpoints
│   │   ├── files.py           # File management
│   │   ├── p2p_transfer.py    # P2P transfer
│   │   ├── updates.py         # Update checking
│   │   └── __init__.py
│   ├── Dockerfile
│   ├── requirements.txt
│   └── __init__.py
│
├── frontend/                   # Flet frontend
│   ├── app.py                 # Main application
│   ├── api_client.py          # API communication
│   ├── theme.py               # UI theming
│   ├── update_manager.py      # Update handling
│   ├── views/                 # UI screens
│   │   ├── login.py           # Login screen
│   │   ├── chats.py           # Chat list
│   │   ├── message_view.py    # Chat messages
│   │   ├── file_upload.py     # File upload
│   │   ├── permissions.py     # Permissions UI (6 permissions)
│   │   ├── settings.py        # Settings screen
│   │   ├── saved_messages.py  # Saved messages
│   │   └── __init__.py
│   ├── assets/                # Images, icons
│   ├── android/               # Android customization
│   ├── Dockerfile
│   ├── requirements.txt
│   └── __init__.py
│
├── scripts/                    # Utility scripts
│   └── seed_mongodb.py         # Database seeding
│
├── data/                       # Data storage
│   ├── files/                 # User files
│   ├── uploads/               # Uploaded files
│   └── tmp/                   # Temporary files
│
├── build_apk.py               # APK builder (Python)
├── build_apk.bat              # APK builder (Windows)
├── build_apk.sh               # APK builder (Linux/macOS)
├── docker-compose.yml         # Docker services
├── nginx.conf                 # Nginx configuration
├── pyproject.toml             # Project metadata
├── APK_BUILD_GUIDE.md         # Quick APK reference
├── APK_BUILD_COMPLETE.md      # Complete APK guide
├── PERMISSIONS_SYSTEM.md      # Permissions documentation
└── README.md                  # This file
```

---

## ⚙️ Configuration

### Backend Configuration (`backend/config.py`)
```python
# MongoDB (VPS)
MONGODB_URL = "mongodb://139.59.82.105:27017"
DATABASE_NAME = "zaply"

# JWT
SECRET_KEY = "your-secret-key-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Server
HOST = "0.0.0.0"
PORT = 8000
```

### Frontend Configuration (`frontend/app.py`)
```python
# API Settings (VPS)
API_BASE_URL = "http://139.59.82.105:8000"
API_TIMEOUT = 30

# App Settings
APP_NAME = "Zaply"
APP_VERSION = "1.0.0"
```

### Docker Environment (`.env`)
```
MONGODB_URL=mongodb://mongo:27017
DATABASE_NAME=zaply
SECRET_KEY=your-secret-key
API_PORT=8000
```

---

## 📦 Building APK

### Prerequisites for APK Build
- Android SDK (API 31+)
- Java Development Kit (JDK 11+)
- Flutter SDK
- ~10 GB disk space
- 10-15 minutes build time

### Build Commands

#### Option 1: Standard Build (Recommended)
```bash
flet build apk --compile-app --cleanup-app --split-per-abi --verbose
```
- **Size**: 80-120 MB total (split across architectures)
- **Time**: 10-15 minutes
- **Best for**: Google Play Store distribution

#### Option 2: Minimal Build (Smallest)
```bash
flet build apk --compile-app --cleanup-app --arch arm64-v8a --verbose
```
- **Size**: 60-80 MB (ARM64 only)
- **Time**: 8-12 minutes
- **Best for**: Testing and quick deployment

#### Option 3: Using Build Script
```bash
# Windows
.\build_apk.bat standard

# Linux/macOS
./build_apk.sh standard

# Python
python build_apk.py standard
```

### Build Output
APK files are located at:
```
build/android/app/build/outputs/apk/release/
```

### Installing on Device
```bash
# Connect device via USB and enable USB debugging
adb install -r build/android/app/build/outputs/apk/release/app-release.apk

# Or install specific APK if split
adb install-multiple build/android/app/build/outputs/apk/release/*.apk
```

---

## 🚀 Deployment

### Docker Deployment (Recommended)

#### Build Images
```bash
docker-compose build
```

#### Start Services
```bash
docker-compose up -d
```

#### Access Application (VPS)
- **Frontend**: http://139.59.82.105:8550
- **Backend API**: http://139.59.82.105:8000
- **API Docs**: http://139.59.82.105:8000/docs
- **MongoDB**: 139.59.82.105:27017

#### View Logs
```bash
docker-compose logs -f backend
docker-compose logs -f frontend
docker-compose logs -f mongo
```

### Production Checklist
- [ ] Change `SECRET_KEY` in environment
- [ ] Enable HTTPS/SSL certificates
- [ ] Configure firewall rules
- [ ] Set up database backups
- [ ] Configure logging and monitoring
- [ ] Set up CI/CD pipeline
- [ ] Enable CORS properly
- [ ] Use environment variables for secrets

---

## 🔧 Troubleshooting

### ⚠️ MongoDB Connection Issues (Docker vs Local Service)

**Problem:** Backend can't connect to MongoDB, or local mongod service keeps failing

**Root Cause:** 
- Docker containers use internal service names (mongodb:27017) for container-to-container communication
- Local VPS mongod service (exit-code 14) is deprecated - use Docker MongoDB instead
- Port 27017 conflicts between local service and Docker container

**Complete Fix (Recommended):**
```bash
# On VPS
cd /hypersend/Hypersend

# 1. Stop and disable local MongoDB service (free port 27017)
sudo systemctl stop mongod 2>/dev/null || true
sudo systemctl disable mongod 2>/dev/null || true

# 2. Kill any process using port 27017
sudo lsof -ti :27017 | xargs -r sudo kill -9 2>/dev/null || true

# 3. Pull latest fixes from GitHub
git pull origin main

# 4. Clean up Docker resources
docker compose down -v
docker volume rm hypersend_mongodb_data hypersend_mongodb_config 2>/dev/null || true

# 5. Build and start services
docker compose up -d --build

# 6. Wait for services to initialize
sleep 60

# 7. Verify services are healthy
docker compose ps

# 8. Test connectivity
curl http://localhost:8000/health
```

**Verify MongoDB is working inside Docker:**
```bash
# Test MongoDB connectivity from backend
docker exec hypersend_backend curl -s http://localhost:8000/health

# Check MongoDB logs
docker compose logs mongodb --tail=20

# Check backend logs for connection messages
docker compose logs backend --tail=20
```

**Important Configuration Changes:**
- ✅ `MONGODB_URI` in docker-compose.yml now uses `mongodb:27017` (Docker service name)
- ✅ Backend config.py updated to use Docker service name as default
- ✅ This allows container-to-container communication on internal Docker network (172.20.0.0/16)

### Port 27017 Already in Use (MongoDB conflict)

**Cause:** Old MongoDB container or process still using the port

**Quick Fix:**
```bash
# On VPS
docker compose down -v
docker volume rm hypersend_mongodb_data hypersend_mongodb_config 2>/dev/null || true
sudo systemctl stop mongod 2>/dev/null || true
sudo lsof -ti :27017 | xargs -r kill -9 2>/dev/null || true
docker compose up -d --build
docker compose ps  # Verify all services running
```

### Backend Connection Error: "Unable to connect to 139.59.82.105:8000"

**Cause:** Backend services not running on VPS

**Quick Fix (Fastest):**
```bash
cd /hypersend/Hypersend && bash FIX_VPS.sh
```

**Manual Fix:**
```bash
ssh root@139.59.82.105
cd /hypersend/Hypersend
git pull origin main
docker compose down -v
docker compose up -d --build
sleep 60
docker compose ps
curl http://localhost:8000/health
```

### Service Not Responding

**Check service status:**
```bash
docker compose ps
```

**View logs:**
```bash
docker compose logs backend    # Backend API
docker compose logs mongodb    # Database
docker compose logs nginx      # Web server
docker compose logs frontend   # Frontend
```

**Restart services:**
```bash
docker compose restart
```

**Verify MongoDB connection from backend:**
```bash
docker compose logs backend | grep -i "mongodb\|connected"
```

---

## 📚 API Documentation

### Auto-Generated Docs
Once backend is running on your VPS, visit:
- **Swagger UI**: http://139.59.82.105:8000/docs
- **ReDoc**: http://139.59.82.105:8000/redoc

### Key Endpoints

#### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login user
- `POST /api/auth/refresh` - Refresh token
- `POST /api/auth/logout` - Logout user

#### Users
- `GET /api/users/me` - Get current user
- `GET /api/users/{id}` - Get user by ID
- `GET /api/users/search` - Search users
- `PUT /api/users/{id}` - Update user profile
- `PUT /api/users/{id}/permissions` - Update permissions

#### Messages
- `GET /api/chats` - Get chat list
- `GET /api/chats/{id}/messages` - Get messages
- `POST /api/chats/{id}/messages` - Send message
- `WS /api/ws/{user_id}` - WebSocket connection

#### Files
- `POST /api/files/upload` - Upload file
- `GET /api/files/{id}` - Download file
- `GET /api/files/list` - List user files
- `DELETE /api/files/{id}` - Delete file

#### Permissions
- `GET /api/permissions/{user_id}` - Get user permissions
- `POST /api/permissions/{user_id}/allow` - Allow permission
- `POST /api/permissions/{user_id}/disallow` - Disallow permission

---

## 🔐 Security Features

### Authentication
- JWT-based authentication
- Secure password hashing (bcrypt)
- Refresh token rotation
- Session management

### Data Protection
- Encrypted database connections
- HTTPS/TLS support
- File upload validation
- Input sanitization

### Permissions
- Granular permission controls
- User-friendly permission requests
- Audit logging
- Permission revocation

---

## 🧪 Testing

### Run Tests
```bash
# Backend tests
cd backend
pytest tests/

# Frontend tests
cd frontend
pytest tests/
```

### Seed Database
```bash
python scripts/seed_mongodb.py
```

Creates 6,350+ test documents including:
- 100 users with profiles
- 50 active conversations
- 1,000+ messages
- 100+ shared files

---

## 📱 Supported Platforms

| Platform | Status | Notes |
|----------|--------|-------|
| **Android** | ✅ Full | Flet build apk |
| **iOS** | ✅ Full | Requires macOS, Xcode |
| **Windows** | ✅ Full | Native Windows app |
| **macOS** | ✅ Full | Intel & Apple Silicon |
| **Linux** | ✅ Full | GTK/WebView |
| **Web** | ✅ Full | Browser-based |

---

## 🐛 Troubleshooting

### Common Issues

#### MongoDB Connection Error
```bash
# Check MongoDB is running
docker ps | grep mongo

# Or start MongoDB
docker-compose up -d mongo
```

#### APK Build Fails
```bash
# Clear cache and rebuild
rm -rf build .flet .gradle
flet build apk --compile-app --cleanup-app --split-per-abi --verbose

# Check Android SDK
flutter doctor
```

#### Port Already in Use
```bash
# Windows
netstat -ano | findstr :8000
taskkill /PID <pid> /F

# Linux/macOS
lsof -i :8000
kill -9 <pid>
```

#### Module Not Found
```bash
# Ensure virtual environment is activated
pip install -r requirements.txt
pip install -r backend/requirements.txt
pip install -r frontend/requirements.txt
```

---

## 📖 Additional Documentation

- [APK Build Guide](APK_BUILD_GUIDE.md) - Quick reference for building APKs
- [APK Build Complete](APK_BUILD_COMPLETE.md) - Comprehensive build guide
- [Permissions System](PERMISSIONS_SYSTEM.md) - Permission implementation details
- [MongoDB Setup](scripts/seed_mongodb.py) - Database initialization

---

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Code Style
- Follow PEP 8 for Python
- Use type hints
- Write docstrings
- Test your changes

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👥 Authors & Contributors

- **Mayan** - Initial development & maintenance
- **Contributors** - See [CONTRIBUTORS.md](CONTRIBUTORS.md)

---

## 🙏 Acknowledgments

- **Flet** - Flutter for Python UI framework
- **FastAPI** - Modern Python web framework
- **MongoDB** - NoSQL database
- **Flutter** - Cross-platform development
- **Community** - For feedback and contributions

---

## 📞 Support & Contact

### Get Help
- 📧 **Email**: support@zaply.dev
- 💬 **Discussions**: GitHub Discussions
- 🐛 **Issues**: GitHub Issues
- 📚 **Wiki**: GitHub Wiki

### Social Media
- Twitter: [@ZaplyApp](https://twitter.com/zaplyapp)
- Discord: [Zaply Community](https://discord.gg/zaply)

---

## 🗺️ Roadmap

### Version 1.1 (Q1 2025)
- [ ] Voice calls
- [ ] Video calls
- [ ] Message encryption
- [ ] Cloud backup

### Version 1.2 (Q2 2025)
- [ ] Group chats
- [ ] Channel support
- [ ] Story feature
- [ ] Media gallery

### Version 2.0 (H2 2025)
- [ ] AI-powered features
- [ ] Plugin system
- [ ] Advanced analytics
- [ ] Enterprise features

---

## 📊 Project Stats

- **Lines of Code**: 15,000+
- **Test Coverage**: 85%+
- **Supported Languages**: 15+
- **Devices Supported**: 6+ platforms
- **API Endpoints**: 25+
- **Database Documents**: 6,350+ (with seeding)

---

**Last Updated**: December 2, 2025

**Version**: 1.0.0

Made with ❤️ by Mayan
