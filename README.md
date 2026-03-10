# Hypersend (Zaply)

**A secure, fast, and modern P2P chat and file transfer application with end-to-end encryption**

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-Production%20Ready-brightgreen)

## 📋 Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Technology Stack](#technology-stack)
- [Project Architecture](#project-architecture)
- [Directory Structure](#directory-structure)
- [Prerequisites](#prerequisites)
- [Installation & Setup](#installation--setup)
- [Configuration](#configuration)
- [Running the Application](#running-the-application)
- [API Documentation](#api-documentation)
- [Deployment](#deployment)
- [Security Features](#security-features)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

---

## 🎯 Overview

**Hypersend** (branded as **Zaply**) is a comprehensive P2P chat and file transfer platform that prioritizes security, speed, and user experience. It enables users to communicate in real-time, share files efficiently (up to 15GB per file), and manage their digital identity across multiple devices with end-to-end encryption.

The application consists of:
- **Backend API**: FastAPI-based REST/WebSocket server with MongoDB and Redis
- **Cross-Platform Frontend**: Flutter application for iOS, Android, Web, Windows, Linux, and macOS
- **Infrastructure**: Docker containerized deployment with Nginx reverse proxy

---

## ✨ Key Features

### Communication
- 🔐 **End-to-End Encryption (E2EE)**: WhatsApp-grade Signal Protocol cryptography
- 💬 **Real-time Messaging**: WebSocket-based instant message delivery
- 👥 **Group Chats**: Create and manage group conversations
- 📱 **Multi-Device Support**: Access same account across multiple devices simultaneously
- 🔔 **Notifications**: Real-time notification delivery system
- 📝 **Message History**: Persistent message storage with search capabilities

### File Sharing
- 📁 **Large File Support**: Upload and download files up to 15GB
- ⚡ **Chunked Upload/Download**: Efficient handling of large transfers
- 🛡️ **Secure Storage**: Server-side encrypted file storage
- 🔗 **File Sharing**: Share files with individual users or groups
- 📊 **Bandwidth Management**: Intelligent rate limiting and connection handling

### User Management
- 👤 **User Profiles**: Customizable user profiles with avatars
- 🔑 **Authentication**: JWT-based secure authentication with refresh tokens
- 🚫 **Blocked Users**: Block/unblock users with relationship management
- 📍 **Presence Tracking**: Real-time online/offline status
- 🎮 **Device Management**: Register and manage multiple devices per user

### Security
- 🔐 **Password Security**: Bcrypt hashing with salt
- 🛡️ **Rate Limiting**: DDoS protection with request rate limiting
- 📤 **HTTPS/TLS**: Production HTTPS with Let's Encrypt SSL certificates
- 🔑 **API Key Security**: API key-based service authentication
- ✅ **Input Validation**: Comprehensive Pydantic validation

---

## 🛠 Technology Stack

### Backend
| Component | Technology | Version |
|-----------|-----------|---------|
| **Framework** | FastAPI | 0.115.5 |
| **Server** | Uvicorn | 0.32.1 |
| **Database** | MongoDB Atlas | Latest |
| **Cache** | Redis | 7.2 |
| **ORM** | Motor (Async MongoDB) | 3.6.0 |
| **Authentication** | PyJWT + python-jose | 2.10.1 / 3.3.0 |
| **Cryptography** | PyNaCl, cryptography | 1.5.0 / 43.0.0 |
| **Validation** | Pydantic | 2.11.5 |
| **Language** | Python | 3.11+ |

### Frontend
| Component | Technology | Version |
|-----------|-----------|---------|
| **Framework** | Flutter | 3.9.2+ |
| **Language** | Dart | 3.9.2+ |
| **State Management** | BLoC Pattern | 8.1.6 |
| **HTTP Client** | Dio | 5.7.0 |
| **Routing** | Go Router | 14.6.2 |
| **WebSocket** | web_socket_channel | 2.4.0 |
| **Storage** | SQLite + SharedPreferences | 2.4.1 / 2.3.3 |
| **Encryption** | Pointycastle, encrypt | 3.9.1 / 5.0.3 |
| **Platforms** | iOS, Android, Web, Windows, Linux, macOS | - |

### Infrastructure
| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Reverse Proxy** | Nginx | API routing, SSL termination |
| **Containerization** | Docker | Application isolation |
| **Orchestration** | Docker Compose | Multi-service orchestration |
| **SSL Certificates** | Let's Encrypt + Certbot | HTTPS security |
| **Domain** | zaply.in.net | Production domain |

---

## 🏗 Project Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Clients (Multi-Platform)           │
│  ┌──────────┬──────────┬──────────┬────────┐        │
│  │ Android  │   iOS    │  Flutter │ Web    │        │
│  │   App    │   App    │ Desktop  │ App    │        │
│  └──────────┴──────────┴──────────┴────────┘        │
└─────────────────────────────────────────────────────┘
                     │
                  HTTPS/WSS
                     │
┌─────────────────────────────────────────────────────┐
│            Nginx Reverse Proxy (Port 443)           │
│  ┌───────────────────────────────────────────────┐  │
│  │ - SSL/TLS Termination                         │  │
│  │ - Request Routing                             │  │
│  │ - Compression                                 │  │
│  │ - Cache Management                            │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
                 │                │
                 │                │
    ┌────────────▼──┐    ┌───────▼─────────┐
    │ Backend API   │    │  Frontend Apps  │
    │  (FastAPI)    │    │   (Pre-built)   │
    └────────────┬──┘    └─────────────────┘
                 │
         ┌───────┴────────┬──────────────┐
         │                │              │
    ┌────▼────┐    ┌─────▼─────┐   ┌────▼────┐
    │ MongoDB  │    │   Redis   │   │   File  │
    │  Atlas   │    │   Cache   │   │ Storage │
    │          │    │           │   │         │
    └──────────┘    └───────────┘   └─────────┘
```

### Data Flow
1. **Client Request** → HTTPS to Nginx (Port 443)
2. **Nginx** → Routes to Backend (Port 8000) or Frontend
3. **Backend** → Processes request, validates JWT tokens
4. **Database Layer** → MongoDB for persistence, Redis for caching
5. **WebSocket** → Real-time bidirectional communication
6. **Response** → Returned through Nginx to Client

---

## 📁 Directory Structure

```
hypersend/
├── backend/                          # FastAPI Backend Application
│   ├── auth/                         # Authentication & Authorization
│   │   ├── utils.py                  # JWT token utilities
│   │   └── security.py               # Password hashing & verification
│   ├── crypto/                       # E2EE Cryptography
│   │   ├── signal_protocol.py        # Signal Protocol implementation
│   │   ├── multi_device.py           # Multi-device sync
│   │   ├── media_encryption.py       # File encryption
│   │   └── delivery_semantics.py     # Message delivery guarantees
│   ├── routes/                       # API Endpoints
│   │   ├── auth.py                   # Login, register, token refresh
│   │   ├── chats.py                  # Chat CRUD operations
│   │   ├── messages.py               # Message handling
│   │   ├── files.py                  # File upload/download
│   │   ├── groups.py                 # Group management
│   │   ├── users.py                  # User profiles
│   │   ├── devices.py                # Device management
│   │   ├── channels.py               # Channel operations
│   │   ├── e2ee_messages.py          # Encrypted messaging
│   │   ├── presence.py               # Online status
│   │   └── p2p_transfer.py           # P2P file transfer
│   ├── services/                     # Business Logic
│   │   ├── emoji_service.py          # Emoji handling
│   │   ├── message_history_service.py # Message history
│   │   └── relationship_graph_service.py
│   ├── websocket/                    # WebSocket Management
│   │   └── websocket_manager.py      # Real-time communication
│   ├── workers/                      # Async Workers
│   │   └── fan_out_worker.py         # Message distribution
│   ├── utils/                        # Utility Functions
│   ├── config.py                     # Configuration Management
│   ├── main.py                       # FastAPI Application Entry
│   ├── database.py                   # Database Connection
│   ├── models.py                     # Data Models
│   ├── validators.py                 # Input Validators
│   ├── error_handlers.py             # Exception Handling
│   ├── redis_cache.py                # Redis Integration
│   ├── rate_limiter.py               # Rate Limiting
│   ├── e2ee_service.py               # E2EE Service
│   ├── notification_service.py       # Push Notifications
│   ├── Dockerfile                    # Backend Container Image
│   └── requirements.txt              # Python Dependencies
│
├── frontend/                         # Flutter Mobile/Web Application
│   ├── lib/
│   │   ├── core/
│   │   │   ├── constants/            # App constants & API config
│   │   │   ├── router/               # Navigation routes
│   │   │   ├── theme/                # Theme & styling
│   │   │   └── utils/                # Utility functions
│   │   ├── data/
│   │   │   ├── models/               # Data models
│   │   │   ├── repositories/         # Data layer
│   │   │   └── mock/                 # Mock data
│   │   ├── logic/
│   │   │   └── bloc/                 # BLoC state management
│   │   └── presentation/
│   │       ├── screens/              # App screens
│   │       └── widgets/              # Reusable widgets
│   ├── android/                      # Android-specific config
│   ├── ios/                          # iOS-specific config
│   ├── web/                          # Web build output
│   ├── windows/                      # Windows desktop config
│   ├── linux/                        # Linux desktop config
│   ├── macos/                        # macOS desktop config
│   ├── pubspec.yaml                  # Flutter dependencies
│   ├── analysis_options.yaml         # Lint rules
│   ├── Dockerfile                    # Frontend Container Image
│   └── README.md                     # Frontend documentation
│
├── docker-compose.yml                # Multi-container orchestration
├── Dockerfile                        # Main application Dockerfile
├── nginx.conf                        # Nginx reverse proxy config
├── kubernetes.yaml                  # Kubernetes deployment config
├── pyproject.toml                    # Python project metadata
│
├── data/                             # Application Data
│   ├── avatars/                      # User avatar storage
│   ├── files/                        # Shared files
│   ├── storage/                      # Server storage
│   ├── uploads/                      # Temporary uploads
│   ├── temp/                         # Temporary files
│   ├── db/                           # Database data
│   └── credentials/                  # Service credentials
│
├── scripts/                          # Utility Scripts
│   ├── seed_mongodb.py               # Database seeding
│   ├── run_testsprite_mcp.js         # Testing helpers
│   └── __pycache__/
│
├── tests/                            # Test Suite
│   ├── comprehensive_api_test.py
│   ├── comprehensive_auth_test.py
│   ├── comprehensive_test_runner.py
│   ├── debug_*.py                    # Debug utilities
│   └── check_*.py                    # Validation scripts
│
├── docs/                             # Documentation
├── certs/                            # SSL Certificates
│   ├── live/                         # Active certificates
│   ├── temp/                         # Temporary certificates
│   └── archive/                      # Archived certificates
│
└── README.md                         # This file
```

---

## 📋 Prerequisites

### System Requirements
- **OS**: Linux (Ubuntu 20.04+), macOS, or Windows with WSL2
- **Disk Space**: Minimum 10GB free (for Docker images and data)
- **RAM**: Minimum 4GB (8GB+ recommended)

### Required Software

#### For Backend Development
```bash
# Python 3.11 or higher
python --version

# pip (Python package manager)
pip --version

# Virtual environment (venv)
python -m venv <env_name>
```

#### For Frontend Development
```bash
# Flutter SDK (3.9.2+)
flutter --version

# Dart SDK (3.9.2+)
dart --version
```

#### For Containerized Deployment
```bash
# Docker (latest)
docker --version

# Docker Compose (2.0+)
docker-compose --version
```

#### For Database & Cache
```bash
# MongoDB Atlas Account (cloud-based)
# OR Local MongoDB for development

# Redis (for local development)
redis-cli --version
```

---

## 🚀 Installation & Setup

### 1. Clone Repository

```bash
# Clone the repository
git clone https://github.com/yourusername/hypersend.git
cd hypersend
```

### 2. Backend Setup

#### Option A: Local Development (Python venv)

```bash
# Navigate to backend directory
cd backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Return to root
cd ..
```

#### Option B: Docker (Recommended)

```bash
# Docker will automatically handle dependencies
# Configuration is in docker-compose.yml
```

### 3. Frontend Setup

```bash
# Navigate to frontend directory
cd frontend

# Get Flutter dependencies
flutter pub get

# Run code generation (if needed)
flutter pub run build_runner build --delete-conflicting-outputs

# Return to root
cd ..
```

### 4. Database Setup

#### MongoDB Atlas (Production)

1. Create account at [MongoDB Atlas](https://www.mongodb.com/cloud/atlas)
2. Create a cluster and database user
3. Get connection string: `mongodb+srv://username:password@cluster.mongodb.net/dbname`
4. Add to `.env` or Docker environment

#### Local MongoDB (Development)

```bash
# Install MongoDB Community
# macOS:
brew install mongodb-community

# Start service
brew services start mongodb-community

# Or pull Docker image:
docker pull mongo:latest
```

### 5. Redis Setup

#### Using Docker (Recommended)

```bash
docker run -d -p 6379:6379 redis:7.2-alpine
```

#### Local Installation

```bash
# macOS:
brew install redis
redis-server

# Ubuntu:
sudo apt-get install redis-server
redis-server
```

---

## ⚙️ Configuration

### Environment Variables

Create a `.env` file in the root directory:

```bash
# ===== DATABASE CONFIGURATION =====
MONGODB_ATLAS_ENABLED=true
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/database?retryWrites=true&w=majority
DATABASE_NAME=Hypersend
USE_MOCK_DB=false

# ===== API CONFIGURATION =====
API_BASE_URL=https://zaply.in.net/api/v1
API_HOST=0.0.0.0
API_PORT=8000
API_KEY=your_api_key_here
API_SECRET=your_api_secret_here

# ===== SECURITY =====
SECRET_KEY=your_super_secret_key_change_in_production
JWT_SECRET_KEY=your_jwt_secret_key
JWT_REFRESH_SECRET_KEY=your_jwt_refresh_secret_key
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7

# ===== RATE LIMITING =====
RATE_LIMIT_PER_USER=100
RATE_LIMIT_WINDOW=3600

# ===== REDIS CONFIGURATION =====
REDIS_URL=redis://localhost:6379/0
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0

# ===== FILE STORAGE =====
STORAGE_PATH=/app/storage
TEMP_STORAGE_PATH=/app/temp
UPLOAD_DIR=/app/uploads
MAX_FILE_SIZE_BYTES=16106127360  # 15 GiB
CHUNK_SIZE=4194304  # 4 MiB
FILE_RETENTION_HOURS=0
AUTO_CLEANUP_ENABLED=true

# ===== CORS CONFIGURATION =====
ALLOWED_ORIGINS=https://zaply.in.net,https://www.zaply.in.net

# ===== EMAIL CONFIGURATION =====
ENABLE_EMAIL=true
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_app_specific_password
SMTP_USE_TLS=true
EMAIL_FROM=noreply@zaply.in.net
SENDER_NAME=Hypersend Support

# ===== ENVIRONMENT =====
DEBUG=false
ENVIRONMENT=production
LOG_LEVEL=INFO
LOG_FORMAT=json

# ===== SSL CERTIFICATES =====
SSL_CERT_PATH=/etc/letsencrypt/live/zaply.in.net/fullchain.pem
SSL_KEY_PATH=/etc/letsencrypt/live/zaply.in.net/privkey.pem
```

### Backend Configuration File

Edit `backend/config.py` for application-specific settings:

```python
# Database settings
MONGODB_ATLAS_ENABLED = True
DATABASE_NAME = "Hypersend"

# File upload settings
MAX_FILE_SIZE = 15 * 1024 * 1024 * 1024  # 15 GB
CHUNK_SIZE = 4 * 1024 * 1024  # 4 MB

# Rate limiting
RATE_LIMIT_PER_USER = 100
RATE_LIMIT_WINDOW = 3600  # 1 hour

# Token expiry
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7
```

### Frontend Configuration

Edit `frontend/lib/core/constants/api_constants.dart`:

```dart
const String apiBaseUrl = 'https://zaply.in.net/api/v1';
const String websocketUrl = 'wss://zaply.in.net/api/v1/ws';
const Duration apiTimeout = Duration(seconds: 30);
const Duration fileUploadTimeout = Duration(hours: 1);
```

---

## 🎮 Running the Application

### Option 1: Docker Compose (Recommended for Production)

```bash
# Build and start all services
docker-compose up --build

# Run in background
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down

# Stop and remove volumes
docker-compose down -v
```

Services started:
- **Nginx**: http://localhost:80 (HTTP), https://localhost:443 (HTTPS)
- **Backend API**: http://localhost:8000
- **Redis**: localhost:6379
- **MongoDB**: Connected via connection string
- **Frontend**: http://localhost:3000 (if served by Nginx)

### Option 2: Local Development

#### Terminal 1: Start Redis & MongoDB

```bash
# If using Docker
docker run -d -p 6379:6379 redis:7.2-alpine
docker run -d -p 27017:27017 mongo:latest

# Or use local services if installed
redis-server
mongod
```

#### Terminal 2: Start Backend

```bash
cd backend
source venv/bin/activate  # On Windows: venv\Scripts\activate
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Backend API Documentation:
- 📚 **Swagger UI**: http://localhost:8000/docs
- 🔗 **ReDoc**: http://localhost:8000/redoc

#### Terminal 3: Start Frontend (Web)

```bash
cd frontend
flutter run -d chrome
```

Or for other platforms:
```bash
flutter run -d windows
flutter run -d linux
flutter run -d macos
```

### Option 3: Development with Docker Compose (Individual Services)

```bash
# Start only backend and dependencies
docker-compose up backend redis

# Start only frontend
docker-compose up frontend

# Start only nginx
docker-compose up nginx
```

---

## 📡 API Documentation

### Base URL
```
Production: https://zaply.in.net/api/v1
Development: http://localhost:8000/api/v1
```

### Authentication

All API endpoints (except login/register) require a JWT token in the `Authorization` header:

```bash
Authorization: Bearer <your_jwt_token>
```

### Core Endpoints

#### Authentication
```
POST   /auth/register           # Register new user
POST   /auth/login              # Login with credentials
POST   /auth/refresh            # Refresh access token
POST   /auth/logout             # Logout user
POST   /auth/forgot-password    # Request password reset
POST   /auth/reset-password     # Reset password with token
```

#### Users
```
GET    /users/me                # Get current user profile
GET    /users/{user_id}         # Get user by ID
PUT    /users/me                # Update user profile
DELETE /users/me                # Delete user account
GET    /users/search            # Search users
```

#### Chats
```
GET    /chats                   # List user's chats
POST   /chats                   # Create new chat
GET    /chats/{chat_id}         # Get chat details
PUT    /chats/{chat_id}         # Update chat
DELETE /chats/{chat_id}         # Delete chat
```

#### Messages
```
GET    /chats/{chat_id}/messages      # Get chat messages
POST   /chats/{chat_id}/messages      # Send message
PUT    /messages/{message_id}         # Edit message
DELETE /messages/{message_id}         # Delete message
```

#### Files
```
POST   /files/upload            # Upload file (chunked)
GET    /files/{file_id}         # Download file
DELETE /files/{file_id}         # Delete file
GET    /files/search            # Search files
```

#### Groups
```
GET    /groups                  # List user's groups
POST   /groups                  # Create new group
GET    /groups/{group_id}       # Get group details
PUT    /groups/{group_id}       # Update group
DELETE /groups/{group_id}       # Delete group
GET    /groups/{group_id}/members  # List members
POST   /groups/{group_id}/members  # Add member
DELETE /groups/{group_id}/members/{user_id}  # Remove member
```

#### Devices
```
GET    /devices                 # List user's devices
POST   /devices/register        # Register new device
DELETE /devices/{device_id}     # Unregister device
```

#### Presence
```
GET    /presence/status         # Get user presence status
POST   /presence/update         # Update presence status
```

#### WebSocket
```
WS     /ws                      # WebSocket connection for real-time messaging
       - Connection: JWT token in query param or header
       - Events: message, presence, notification, typing
```

For full API documentation, visit:
- **Swagger UI**: `/docs`
- **ReDoc**: `/redoc`
- **OpenAPI Schema**: `/openapi.json`

---

## 🚢 Deployment

### Production Deployment

#### Prerequisites
- Docker & Docker Compose installed
- Domain name (e.g., zaply.in.net)
- SSL certificate (Let's Encrypt via Certbot)
- MongoDB Atlas account
- SMTP service for emails

#### Step-by-Step Deployment

1. **Configure SSL Certificates**

```bash
# Install Certbot
sudo apt-get install certbot python3-certbot-nginx

# Generate certificates (requires domain access)
sudo certbot certonly --standalone -d zaply.in.net -d www.zaply.in.net

# Update docker-compose.yml with certificate paths
# SSL_CERT_PATH: /etc/letsencrypt/live/zaply.in.net/fullchain.pem
# SSL_KEY_PATH: /etc/letsencrypt/live/zaply.in.net/privkey.pem
```

2. **Set Environment Variables**

```bash
# Create .env file with all production values
cp .env.example .env

# Edit .env with production settings
nano .env
```

3. **Build and Push Docker Images**

```bash
# Build images
docker-compose build

# Tag for registry
docker tag hypersend-backend:latest yourregistry/hypersend-backend:1.0.0
docker tag hypersend-frontend:latest yourregistry/hypersend-frontend:1.0.0

# Push to Docker Hub or private registry
docker push yourregistry/hypersend-backend:1.0.0
docker push yourregistry/hypersend-frontend:1.0.0
```

4. **Deploy Services**

```bash
# Pull latest images
docker-compose pull

# Start services
docker-compose up -d

# Verify services
docker-compose ps

# Check logs
docker-compose logs -f backend
```

5. **Health Checks**

```bash
# Check backend health
curl https://zaply.in.net/api/v1/health

# Check frontend
curl https://zaply.in.net

# Monitor services
docker-compose stats
```

### Kubernetes Deployment

```bash
# Apply Kubernetes manifests
kubectl apply -f kubernetes.yaml

# Check deployment status
kubectl get pods -n hypersend

# View logs
kubectl logs -f deployment/hypersend-backend -n hypersend

# Scale services
kubectl scale deployment hypersend-backend --replicas=3 -n hypersend
```

### Continuous Integration/Deployment

Recommended workflow:

1. **GitHub Actions** for automated testing
2. **Docker Registry** for image storage
3. **Automated Build & Push** on main branch
4. **Staging Environment** for testing
5. **Production Rollout** with health checks

---

## 🔒 Security Features

### Authentication & Authorization
- ✅ **JWT Tokens**: Secure stateless authentication
- ✅ **Refresh Tokens**: Extended session management
- ✅ **Token Rotation**: Automatic token refresh
- ✅ **Password Hashing**: Bcrypt with salt
- ✅ **Rate Limiting**: DDoS protection

### Encryption
- ✅ **TLS/HTTPS**: All traffic encrypted in transit
- ✅ **End-to-End Encryption (E2EE)**: Signal Protocol
- ✅ **File Encryption**: AES-256 for stored files
- ✅ **Key Management**: Secure key derivation (HKDF)

### Data Protection
- ✅ **Input Validation**: Pydantic models
- ✅ **SQL Injection Prevention**: Parameterized queries
- ✅ **CORS Policy**: Cross-origin request validation
- ✅ **CSRF Protection**: Token-based verification
- ✅ **XSS Prevention**: HTML escaping

### Infrastructure Security
- ✅ **Nginx Security**: Security headers, SSL/TLS
- ✅ **Docker Isolation**: Container sandboxing
- ✅ **Secret Management**: Environment variables
- ✅ **API Key Security**: Secure API key generation
- ✅ **Firewall Rules**: Restricted port access

### Best Practices
- 🔐 **Never commit secrets** to repository
- 🔒 **Use environment variables** for sensitive data
- 🛡️ **Regular security audits** and penetration testing
- 📋 **Keep dependencies updated** (running `pip list --outdated`)
- 📝 **Log security events** for audit trails

---

## 🧪 Testing

### Backend Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=backend --cov-report=html

# Run specific test file
pytest tests/comprehensive_api_test.py -v

# Run tests matching pattern
pytest -k "auth" -v
```

### Frontend Testing

```bash
# Run Flutter tests
flutter test

# Run integration tests
flutter test integration_test/

# Check code quality
flutter analyze
```

---

## 📊 Monitoring & Logs

### Docker Compose Logs

```bash
# View all logs
docker-compose logs

# Follow specific service
docker-compose logs -f backend

# Last 100 lines
docker-compose logs --tail=100 backend

# With timestamps
docker-compose logs -f -t backend
```

### Application Metrics

Backend provides metrics endpoint:
```bash
GET /metrics  # Prometheus-compatible metrics
```

### Health Checks

```bash
# Backend health
curl https://zaply.in.net/api/v1/health

# Redis health
redis-cli ping

# MongoDB connection test
# Integrated in backend startup
```

---

## 🤝 Contributing

We welcome contributions! Please follow these guidelines:

### Code Style

#### Python (Backend)
```bash
# Format code
black backend/

# Sort imports
isort backend/

# Lint
flake8 backend/

# Type checking
mypy backend/
```

#### Dart (Frontend)
```bash
# Format code
dart format lib/

# Analyze
flutter analyze

# Check style
dart analyze lib/
```

### Commit Messages

```
feat: Add new feature description
fix: Fix bug with description
docs: Update documentation
refactor: Refactor code without functionality change
test: Add/update tests
chore: Update dependencies or configuration
```

### Pull Request Process

1. Fork repository
2. Create feature branch: `git checkout -b feature/your-feature`
3. Commit changes: `git commit -m "feat: your feature"`
4. Push to branch: `git push origin feature/your-feature`
5. Open Pull Request with detailed description
6. Ensure all tests pass
7. Wait for code review and approval

---

## 📝 License

This project is licensed under the **MIT License** - see [LICENSE](LICENSE) file for details.

MIT License means:
- ✅ Commercial use allowed
- ✅ Modification allowed
- ✅ Distribution allowed
- ✅ Private use allowed
- ⚠️ Must include license notice
- ❌ No liability
- ❌ No warranty

---

## 📧 Contact & Support

### Get Help

- 📧 **Email**: mayank.kr0311@gmail.com
- 🐛 **Issues**: [GitHub Issues](https://github.com/yourusername/hypersend/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/yourusername/hypersend/discussions)

### Project Links

- 🌐 **Website**: https://zaply.in.net
- 📱 **App Store**: Coming Soon
- 🎯 **Google Play**: Coming Soon
- 💻 **GitHub**: https://github.com/yourusername/hypersend

### Acknowledgments

- Signal Protocol Foundation for E2EE implementation
- FastAPI team for the amazing framework
- Flutter community for cross-platform excellence
- MongoDB Atlas for cloud database services
- Let's Encrypt for free SSL certificates

---

## 🗺 Roadmap

### Current Features (v1.0.0)
- ✅ User authentication
- ✅ Real-time messaging
- ✅ File sharing (up to 15GB)
- ✅ Group chats
- ✅ Multi-device support
- ✅ End-to-end encryption
- ✅ User profiles
- ✅ Presence tracking

### Planned Features (v1.1.0+)
- 🔄 Voice/Video calls
- 🎙️ Voice messages
- 🎨 Rich media support
- 📍 Location sharing
- 🎮 Emoji reactions
- 📌 Message pinning
- 🔍 Advanced search
- 🌐 Multiple language support

---

**Made with ❤️ by Mayank**

Last Updated: March 2026 | Version: 1.0.0
