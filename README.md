# 🚀 Hypersend - Real-Time Messaging & P2P File Transfer Platform

A modern, enterprise-grade, cross-platform messaging and file transfer application built with **Flutter** (frontend), **FastAPI** (backend), and **MongoDB** (database). Featuring real-time chat, secure P2P file transfer, advanced user management, and comprehensive permission controls.

![Status](https://img.shields.io/badge/status-production--ready-brightgreen)
![Python](https://img.shields.io/badge/python-3.11+-blue)
![Flutter](https://img.shields.io/badge/flutter-latest-blue)
![FastAPI](https://img.shields.io/badge/fastapi-0.115.5-green)
![MongoDB](https://img.shields.io/badge/mongodb-7.0-green)
![Docker](https://img.shields.io/badge/docker-supported-blue)
![License](https://img.shields.io/badge/license-MIT-blue)

### 🌟 Highlights
- **Cross-Platform**: Native support for Android, iOS, Windows, macOS, Linux, and Web
- **Production-Ready**: Containerized with Docker, Nginx reverse proxy, and production configurations
- **Secure**: JWT authentication, encrypted file transfers, permission-based access control
- **Scalable**: Async backend, MongoDB for flexible data storage, WebSocket support

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Prerequisites](#prerequisites)
- [Project Structure](#project-structure)
- [Installation & Setup](#installation--setup)
- [Configuration](#configuration)
- [Quick Start](#quick-start)
- [Development](#development)
- [Building & Deployment](#building--deployment)
- [API Documentation](#api-documentation)
- [Database](#database)
- [Docker Setup](#docker-setup)
- [Security](#security)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## 🎯 Overview

Hypersend is a comprehensive communication platform designed to provide users with:
- **Instant Messaging**: Real-time chat with message persistence
- **Secure File Transfer**: P2P file sharing without intermediate storage
- **User Management**: Complete user profile and contact management system
- **Permission Controls**: Fine-grained permission system for device access and data sharing
- **Multi-Platform Support**: Single codebase deployment across multiple platforms

Whether you're looking to deploy a private messaging system, build a team communication platform, or create a secure file-sharing service, Hypersend provides the foundation with enterprise-grade security and scalability.

---

## ✨ Features

### Core Messaging
- 💬 **Real-Time Chat** - WebSocket-based instant messaging with low latency
- 👥 **User Profiles** - Complete user management with avatar and bio support
- 🔐 **Secure Authentication** - JWT-based authentication with refresh tokens and bcrypt password hashing
- 📱 **Cross-Platform** - Native mobile apps (Android/iOS) + desktop (Windows/macOS/Linux) + Web
- 📝 **Message History** - Persistent message storage with MongoDB
- 🔔 **Notifications** - Real-time push notifications for new messages

### P2P File Transfer
- 📤 **Peer-to-Peer File Transfer** - Direct device-to-device file sharing without server intermediary
- 🔒 **Encrypted Connections** - Secure transfer protocols with encryption support
- 📊 **Transfer Management** - Track, pause, resume, and cancel active transfers
- 📁 **Multiple File Support** - Transfer single or multiple files in bulk
- 🚀 **Resume Capability** - Resume interrupted transfers from checkpoint
- 💾 **Automatic Cleanup** - Temporary files auto-cleaned after transfer

### Permissions & Privacy
- 🛡️ **Granular Permission System** - Request and manage device permissions:
  - 📍 Location access (GPS coordinates)
  - 📷 Camera (photo/video capture)
  - 🎤 Microphone (audio recording)
  - 👥 Contacts (address book access)
  - ☎️ Phone (call history, phone number)
  - 💾 Storage (file system access)
- 🔐 **Privacy Controls** - User-controlled permission grants with clear explanations
- 🛑 **Permission Revocation** - Easy permission management and revocation

### User & Contact Management
- 👤 **User Profiles** - Customizable user profiles with status and availability
- 📞 **Contact List** - Manage contacts with search and filtering
- 🚫 **Block/Unblock** - Block users to prevent communication
- 👁️ **Online Status** - Real-time online/offline presence indicators
- 🔍 **User Discovery** - Search and find users by username or email
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
- **Flutter** - Native cross-platform UI framework
- **Dart** - Programming language
- **BLoC Pattern** - State management
- **Dio** - HTTP client
- **GoRouter** - Navigation and routing
- **Intl** - Internationalization support

### Backend
- **FastAPI 0.115.5** - Modern async web framework with automatic OpenAPI docs
- **Motor 3.6.0** - Async MongoDB driver
- **MongoDB 7.0** - NoSQL database with flexible schema
- **Uvicorn** - ASGI server with WebSocket support
- **Pydantic** - Data validation and settings management
- **python-jose** - JWT token handling
- **passlib + bcrypt** - Password hashing and security

### DevOps & Infrastructure
- **Docker** - Containerization for consistent deployment
- **Docker Compose** - Multi-container orchestration (backend + MongoDB)
- **Nginx** - Reverse proxy with SSL/TLS support
- **Python 3.11+** - Runtime environment

### Development & Build
- **Gradle** - Android build system
- **Flutter SDK** - Cross-platform compilation
- **pytest** - Python testing framework
- **Git** - Version control

---

## 📁 Project Structure

```
Hypersend/
├── backend/                      # FastAPI backend
│   ├── main.py                  # Application entry point
│   ├── config.py                # Configuration management
│   ├── database.py              # MongoDB connection
│   ├── models.py                # Data models
│   ├── security.py              # Security utilities
│   ├── mongo_init.py            # Database initialization
│   ├── requirements.txt         # Python dependencies
│   ├── Dockerfile               # Backend container image
│   ├── auth/                    # Authentication module
│   │   ├── __init__.py
│   │   └── utils.py             # Auth utilities (JWT, bcrypt)
│   ├── routes/                  # API route handlers
│   │   ├── auth.py             # Authentication endpoints
│   │   ├── users.py            # User management endpoints
│   │   ├── chats.py            # Chat endpoints
│   │   ├── files.py            # File transfer endpoints
│   │   ├── p2p_transfer.py     # P2P file transfer endpoints
│   │   └── updates.py          # Updates and notifications
│   └── data/                    # Data storage
│       ├── files/              # Uploaded files
│       └── tmp/                # Temporary files
│
├── frontend/                     # Flutter mobile app
│   ├── lib/
│   │   ├── main.dart           # App entry point
│   │   ├── core/               # Core utilities
│   │   │   ├── constants/      # Constants and configs
│   │   │   ├── router/         # Navigation setup
│   │   │   ├── theme/          # UI themes
│   │   │   └── utils/          # Helper functions
│   │   ├── data/               # Data layer
│   │   │   ├── models/         # Data models
│   │   │   └── mock/           # Mock data
│   │   └── presentation/       # UI layer
│   │       ├── screens/        # App screens
│   │       └── widgets/        # Reusable widgets
│   ├── pubspec.yaml           # Flutter dependencies
│   ├── Dockerfile             # Frontend container image
│   ├── android/               # Android-specific files
│   ├── ios/                   # iOS-specific files
│   ├── web/                   # Web-specific files
│   └── windows/               # Windows-specific files
│
├── scripts/
│   └── seed_mongodb.py        # Database seeding script
│
├── tests/
│   ├── test_backend.py        # Backend unit tests
│   └── __pycache__/
│
├── docker-compose.yml         # Multi-container setup
├── nginx.conf                 # Nginx configuration
├── pyproject.toml            # Python project configuration
├── .env.example              # Environment variables template
└── README.md                 # This file
```

---

## 📊 Current Status (December 12, 2025)

### ✅ Completed
- ✅ FastAPI backend with async support
- ✅ JWT-based authentication with refresh tokens
- ✅ MongoDB integration with Motor (async driver)
- ✅ User management (registration, login, profiles)
- ✅ Chat management (private chats and messaging)
- ✅ File upload/download with chunked transfer
- ✅ P2P file transfer endpoints
- ✅ Permission management system
- ✅ User update tracking
- ✅ Backend tests (3/3 passing)
- ✅ Docker containerization
- ✅ Nginx reverse proxy configuration
- ✅ Flutter cross-platform frontend
- ✅ BLoC state management
- ✅ Theme system (Dark/Light modes)

### ⏳ In Progress / TODO
- ⏳ WebSocket for real-time messaging
- ⏳ Push notifications
- ⏳ Voice messages and call features
- ⏳ Audio/Video calls integration
- ⏳ Advanced message search
- ⏳ End-to-end encryption (E2E)
- ⏳ Message reactions and emojis
- ⏳ User presence/typing indicators

---

## 📦 Prerequisites

### System Requirements
- **Python**: 3.11 or higher
- **Node.js**: 18+ (for optional web deployment)
- **MongoDB**: 7.0+ (local or Docker containerized)
- **Docker & Docker Compose** (recommended for production)
- **Git**: For version control

### For Mobile Development (Optional)
- **Java JDK**: 11 or higher (for Android builds)
- **Android SDK**: API level 31+ (minimum API level for APK)
- **Flutter SDK**: Latest stable version
- **Gradle**: Included with Android SDK or standalone

### Development Tools
- **Visual Studio Code** or **Android Studio** (IDE)
- **adb** (Android Debug Bridge)
- **Postman** or **curl** (API testing)

---

## 🚀 Installation & Setup

### Quick Start (Docker - Recommended)

#### 1. Clone Repository
```bash
git clone https://github.com/Mayankvlog/Hypersend.git
cd Hypersend
```

#### 2. Create Environment Configuration
```bash
# Copy example environment file
cp .env.example .env

# Edit .env with your settings
# Windows: notepad .env
# Linux/macOS: nano .env
```

#### 3. Start with Docker Compose
```bash
# Build and start all services (backend, frontend, MongoDB, Nginx)
docker-compose up --build

# Services will be available at:
# - API: http://localhost:8080/api
# - Frontend: http://localhost:8080
# - MongoDB: localhost:27017
```

#### 4. Verify Installation
```bash
# Check API health
curl http://localhost:8080/health

# View logs
docker-compose logs -f backend
docker-compose logs -f mongodb
```

---

### Manual Setup (Local Development)

#### 1. Clone Repository
```bash
git clone https://github.com/Mayankvlog/Hypersend.git
cd Hypersend
```

#### 2. Create Virtual Environment
```bash
# Windows
python -m venv venv
venv\Scripts\activate.ps1

# Linux/macOS
python3 -m venv venv
source venv/bin/activate
```

#### 3. Install Backend Dependencies
```bash
cd backend
pip install -r requirements.txt
cd ..
```

#### 4. Start MongoDB
```bash
# Using Docker (recommended)
docker run -d \
  -p 27017:27017 \
  -v mongodb_data:/data/db \
  --name hypersend_mongodb \
  mongo:7.0

# OR install MongoDB locally
# macOS: brew install mongodb-community
# Windows: Download from https://www.mongodb.com/try/download/community
```

#### 5. Start Backend Server
```bash
cd backend
python main.py

# You should see:
# [START] API starting on 0.0.0.0:8000
# [DB] MongoDB initialization completed
# [START] Uvicorn running on http://0.0.0.0:8000
```

#### 6. Start Frontend (Flutter Web)
```bash
cd frontend
flutter pub get
flutter run -d chrome  # For web
# OR
flutter run -d windows # For desktop Windows
```

---

## ⚙️ Configuration

### Environment Variables (.env)
Create a `.env` file in the project root:

```env
# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
API_DEBUG=true

# MongoDB
MONGODB_URI=mongodb://localhost:27017
MONGODB_NAME=hypersend_db

# Security
SECRET_KEY=your-secret-key-change-this
JWT_ALGORITHM=HS256
JWT_EXPIRATION_HOURS=24
JWT_REFRESH_EXPIRATION_DAYS=7

# CORS
CORS_ORIGINS=["http://localhost:3000", "http://localhost:8080"]

# File Upload
MAX_UPLOAD_SIZE=104857600  # 100MB
UPLOAD_DIR=./data/uploads
TEMP_DIR=./data/tmp

# Nginx Configuration
NGINX_PORT=8080
NGINX_PORT_SSL=8445

# Environment
ENVIRONMENT=development  # development, staging, production
```

### Backend Configuration (config.py)
Key settings you can customize:

```python
# API Settings
API_HOST = "0.0.0.0"
API_PORT = 8000
DEBUG = True

# Database
MONGODB_URI = "mongodb://localhost:27017"
MONGODB_NAME = "hypersend_db"

# Authentication
SECRET_KEY = "your-secret-key"
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24
JWT_REFRESH_EXPIRATION_DAYS = 7

# File Upload
MAX_UPLOAD_SIZE = 100 * 1024 * 1024  # 100MB
```

---

## 🔗 API Documentation

### Interactive API Docs
Once the backend is running, visit these URLs:

- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`
- **OpenAPI JSON**: `http://localhost:8000/openapi.json`

### Key API Endpoints

#### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login with credentials
- `POST /api/auth/refresh` - Refresh JWT token
- `POST /api/auth/logout` - Logout user

#### Users
- `GET /api/users/profile` - Get current user profile
- `PUT /api/users/profile` - Update user profile
- `GET /api/users/search` - Search for users
- `GET /api/users/{user_id}` - Get user details
- `POST /api/users/{user_id}/block` - Block/unblock user

#### Chat & Messages
- `POST /api/chats/create` - Create new chat
- `GET /api/chats/list` - Get all chats
- `GET /api/chats/{chat_id}/messages` - Get chat messages
- `POST /api/chats/{chat_id}/messages` - Send message
- `DELETE /api/messages/{message_id}` - Delete message

#### Files
- `POST /api/files/upload` - Upload file with chunks
- `GET /api/files/{file_id}` - Download file
- `DELETE /api/files/{file_id}` - Delete file
- `GET /api/files/list` - List user files

#### P2P Transfer
- `POST /api/p2p/initiate` - Initiate P2P transfer
- `GET /api/p2p/status/{transfer_id}` - Get transfer status
- `POST /api/p2p/cancel/{transfer_id}` - Cancel transfer

#### Permissions
- `GET /api/permissions` - Get user permissions
- `PUT /api/permissions/{permission_type}` - Update permission
- `DELETE /api/permissions/{permission_type}` - Revoke permission

---

## 🗄️ Database

### MongoDB Schema Overview

#### Users Collection
```json
{
  "_id": ObjectId,
  "username": "john_doe",
  "email": "john@example.com",
  "password_hash": "hashed_password",
  "profile": {
    "avatar": "avatar_url",
    "bio": "User bio",
    "status": "online|offline|away"
  },
  "created_at": ISODate,
  "updated_at": ISODate
}
```

#### Chats Collection
```json
{
  "_id": ObjectId,
  "participants": [ObjectId, ObjectId],
  "chat_type": "private|group|channel",
  "name": "Chat Name",
  "created_at": ISODate,
  "updated_at": ISODate
}
```

#### Messages Collection
```json
{
  "_id": ObjectId,
  "chat_id": ObjectId,
  "sender_id": ObjectId,
  "content": "Message text",
  "message_type": "text|image|file|voice",
  "created_at": ISODate,
  "deleted_at": ISODate
}
```

### Database Initialization
The system automatically initializes MongoDB on startup:
- Creates collections if they don't exist
- Creates necessary indexes for performance
- Seeds sample data (configurable)

---

## 🐳 Docker Setup

### Docker Compose Services

```yaml
services:
  mongodb:
    Image: mongo:7.0
    Ports: 27017:27017
    Volumes: mongodb_data
  
  backend:
    Build: ./backend
    Ports: 8000:8000
    Depends on: mongodb
  
  frontend:
    Build: ./frontend
    Ports: 3000:3000
    Depends on: backend
  
  nginx:
    Image: nginx:alpine
    Ports: 8080:80, 8445:443
    Depends on: backend, frontend
```

### Building Docker Images

```bash
# Build all images
docker-compose build

# Build specific service
docker-compose build backend
docker-compose build frontend

# View built images
docker images | grep hypersend
```

### Running Containers

```bash
# Start all services in background
docker-compose up -d

# Start with logs visible
docker-compose up

# Start specific service
docker-compose up -d backend

# View service status
docker-compose ps

# View logs
docker-compose logs -f
docker-compose logs -f backend
docker-compose logs -f mongodb

# Stop services
docker-compose down

# Remove volumes (clears data!)
docker-compose down -v
```

### Health Checks

```bash
# Check Nginx health
curl http://localhost:8080/health

# Check API health
curl http://localhost:8080/api/health

# Check MongoDB
docker-compose exec mongodb mongosh --eval "db.adminCommand('ping')"
```

---

## 🔐 Security

### Authentication & Authorization
- **JWT Tokens**: Stateless authentication with secure tokens
- **Password Security**: Bcrypt hashing with salt (12 rounds)
- **Refresh Tokens**: Separate tokens for token rotation
- **HTTPS/TLS**: SSL certificate support via Nginx

### Data Security
- **Input Validation**: Pydantic models validate all inputs
- **SQL Injection Prevention**: MongoDB parameterized queries
- **CORS Protection**: Configurable CORS origins
- **Rate Limiting**: Optional rate limiting middleware

### File Security
- **File Upload Validation**: Check file types and sizes
- **Secure Storage**: Files stored outside web root
- **Temporary Cleanup**: Auto-delete temporary files
- **Access Control**: User authorization checks

### Permission Management
- **Granular Permissions**: Fine-grained permission controls
- **User Consent**: Explicit user permission grants
- **Revocation**: Easy permission revocation
- **Audit Logs**: Track permission changes

### Production Recommendations
- ✅ Use strong `SECRET_KEY` (generate with: `openssl rand -hex 32`)
- ✅ Enable HTTPS/TLS in production
- ✅ Use environment variables for sensitive data
- ✅ Set `DEBUG = False` in production
- ✅ Use a production database backup strategy
- ✅ Enable MongoDB authentication
- ✅ Configure firewall rules
- ✅ Use a production ASGI server (Gunicorn/Hypercorn)
- ✅ Implement rate limiting
- ✅ Enable security headers

---

## 📱 Building for Mobile

### Android APK

#### Prerequisites
- Android SDK (API 31+)
- Java JDK 11+
- Flutter SDK
- Gradle

#### Build APK
```bash
cd frontend

# Debug APK
flutter build apk --debug

# Release APK
flutter build apk --release

# Output: build/app/outputs/flutter-apk/app-release.apk
```

#### Install on Device
```bash
# Via adb
adb install build/app/outputs/flutter-apk/app-release.apk

# Via Flutter
flutter install -d <device_id>
```

### iOS Build

```bash
cd frontend

# Debug
flutter build ios --debug

# Release
flutter build ios --release
```

---

## 🚀 Deployment

### Deploying to Production

#### DigitalOcean VPS Setup (Example)

1. **SSH into VPS**
```bash
ssh root@your_vps_ip
```

2. **Install Dependencies**
```bash
apt update && apt upgrade -y
apt install -y docker.io docker-compose git python3 python3-pip

# Add current user to docker group
usermod -aG docker $USER
newgrp docker
```

3. **Clone Repository**
```bash
git clone https://github.com/Mayankvlog/Hypersend.git
cd Hypersend
```

4. **Configure Environment**
```bash
cp .env.example .env
# Edit .env with production settings
nano .env
```

5. **Start Services**
```bash
docker-compose up -d
```

6. **Verify Deployment**
```bash
docker-compose ps
curl https://your_domain/health
```

### Setting Up SSL/TLS

Nginx automatically generates self-signed certificates. For production:

```bash
# Using Let's Encrypt with Certbot
docker-compose down

apt install -y certbot python3-certbot-nginx

certbot certonly --standalone -d your_domain.com

# Update nginx.conf with certificate paths
# Then restart
docker-compose up -d
```

---

## 🧪 Testing

### Running Backend Tests
```bash
cd backend
pip install pytest pytest-asyncio

# Run tests
python -m pytest tests/

# With coverage
python -m pytest --cov=backend tests/

# Verbose output
python -m pytest -v tests/
```

### Test Files
- `tests/test_backend.py` - Core backend tests
  - Authentication tests
  - User management tests
  - Chat functionality tests
  - File upload tests

---

## 🐛 Troubleshooting

### Common Issues

#### MongoDB Connection Error
```
Error: Cannot connect to MongoDB at localhost:27017
```
**Solution:**
```bash
# Check MongoDB status
docker ps | grep mongodb

# Start MongoDB if not running
docker-compose up -d mongodb

# Check MongoDB logs
docker-compose logs mongodb
```

#### Port Already in Use
```
Error: Address already in use: ('::', 8000)
```
**Solution:**
```bash
# Find process using port 8000
netstat -ano | findstr :8000  # Windows
lsof -i :8000  # Mac/Linux

# Kill process
taskkill /PID <pid> /F  # Windows
kill -9 <pid>  # Mac/Linux

# Or change port in .env
API_PORT=8001
```

#### Docker Build Failure
```
Error: Docker build failed
```
**Solution:**
```bash
# Clean build
docker-compose build --no-cache

# Check Docker logs
docker logs <container_id>

# Verify Docker installation
docker --version
docker-compose --version
```

#### JWT Token Invalid
```
Error: Invalid token or expired
```
**Solution:**
- Clear app cache and re-login
- Check `SECRET_KEY` in .env matches across restarts
- Verify JWT_EXPIRATION_HOURS setting
- Check server time is synchronized

#### File Upload Fails
```
Error: File upload failed or timeout
```
**Solution:**
- Check `MAX_UPLOAD_SIZE` in configuration
- Verify disk space: `df -h`
- Check file permissions: `chmod 755 ./data`
- Review backend logs: `docker-compose logs backend`

### Debug Mode
```python
# In backend/config.py
DEBUG = True  # Enable debug output

# In backend/main.py
print(f"[DEBUG] {message}")  # Add debug logs

# View all logs
docker-compose logs -f --all
```

---

## 📚 Additional Resources

### Documentation
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [MongoDB Documentation](https://docs.mongodb.com/)
- [Flutter Documentation](https://flutter.dev/docs)
- [Docker Documentation](https://docs.docker.com/)

### Related Projects
- [FastAPI Blog Tutorial](https://fastapi.tiangolo.com/tutorial/first-steps/)
- [Motor AsyncIO MongoDB Driver](https://motor.readthedocs.io/)
- [Flutter Best Practices](https://flutter.dev/docs/testing/best-practices)

---

## 👤 Author

**Mayank Kumar**
- GitHub: [@Mayankvlog](https://github.com/Mayankvlog)
- Email: mayank.kr0311@gmail.com
- LinkedIn: [Your LinkedIn](your-linkedin-profile)

---

## 🤝 Contributing

Contributions are welcome! Here's how:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Development Guidelines
- Follow PEP 8 for Python code
- Use type hints in Python files
- Write tests for new features
- Update documentation
- Use meaningful commit messages

### Reporting Issues
- Use GitHub Issues to report bugs
- Include steps to reproduce
- Attach error logs
- Specify your environment (OS, Python version, etc.)

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

### MIT License Summary
- ✅ Personal use
- ✅ Modification
- ✅ Distribution
- ❌ Warranty (use at your own risk)
- ❌ Liability

---

## 🎯 Roadmap

### v1.1.0 (Q1 2025)
- [ ] WebSocket real-time messaging
- [ ] Message reactions (emojis)
- [ ] User typing indicators
- [ ] Message threading/replies

### v1.2.0 (Q2 2025)
- [ ] Voice messages
- [ ] Video calls
- [ ] Group video calls
- [ ] Call recording

### v1.3.0 (Q3 2025)
- [ ] End-to-end encryption (E2E)
- [ ] Message search
- [ ] Cloud backup
- [ ] User analytics

### v2.0.0 (Q4 2025)
- [ ] AI-powered chatbot
- [ ] Message translation
- [ ] Advanced permission levels
- [ ] OAuth 2.0 integration

---

## 📞 Support

For support, email mayank.kr0311@gmail.com or open an issue on GitHub.

### Getting Help
1. Check [Troubleshooting](#troubleshooting) section
2. Search [GitHub Issues](https://github.com/Mayankvlog/Hypersend/issues)
3. Review API docs at `/docs`
4. Contact maintainer

---

## 🙏 Acknowledgments

- FastAPI team for the amazing framework
- Flutter community for cross-platform development
- MongoDB for flexible database solution
- All contributors and users of this project

---

**Last Updated**: December 12, 2025
**Status**: ✅ Production Ready
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
- JWT-based authentication with auto-generated secure keys
- Secure password hashing (bcrypt with SHA256 normalization)
- Refresh token rotation
- Session management
- Rate limiting (10 attempts per 5 minutes per IP)
- Account lockout (5 failed attempts = 15 min lockout)
- Minimum 12-character passwords with complexity requirements

### Data Protection
- MongoDB authentication required
- MongoDB port not exposed externally (internal Docker network only)
- Security headers (CSP, X-Frame-Options, etc.)
- File upload validation with checksums
- Input sanitization and XSS protection
- CORS restricted to specific origins

### Permissions
- Granular permission controls
- User-friendly permission requests
- Audit logging
- Permission revocation

### Security Hardening Applied
- Strong password requirements (12+ chars)
- Password strength validation
- Rate limiting on login endpoint
- Account lockout mechanism
- Auto-generated secure SECRET_KEY if not set
- MongoDB port removed from external access
- CORS restricted (no wildcard in production)
- Security headers implemented
- Input validation and sanitization

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
