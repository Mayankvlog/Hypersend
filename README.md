# 🚀 Hypersend - Advanced File Sharing & Real-Time Communication Platform

![Hypersend](https://img.shields.io/badge/Hypersend-Enterprise%20File%20Sharing-blue?style=for-the-badge&logo=fastapi)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115.5-green?style=for-the-badge&logo=fastapi)
![Docker](https://img.shields.io/badge/Docker-Compose-blue?style=for-the-badge&logo=docker)
![MongoDB](https://img.shields.io/badge/MongoDB-7.0-green?style=for-the-badge&logo=mongodb)
![Flutter](https://img.shields.io/badge/Flutter-3.9+-purple?style=for-the-badge&logo=flutter)
![Python](https://img.shields.io/badge/Python-3.11+-yellow?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-brightgreen?style=for-the-badge)

**Hypersend** (also branded as **Zaply**) is an enterprise-grade, secure file sharing and real-time communication platform designed for modern web and mobile applications. It combines the reliability of WhatsApp-style messaging with advanced file transfer capabilities, offering high performance, security, and scalability.

---

## 📋 Table of Contents

1. [🌟 Overview](#-overview)
2. [✨ Key Features](#-key-features)
3. [🏗️ Architecture](#-architecture)
4. [🛠️ Technology Stack](#-technology-stack)
5. [📦 Project Structure](#-project-structure)
6. [⚙️ Installation & Setup](#-installation--setup)
7. [🔧 Configuration](#-configuration)
8. [🚀 Running the Application](#-running-the-application)
9. [📚 API Documentation](#-api-documentation)
10. [🧪 Testing](#-testing)
11. [🔒 Security Features](#-security-features)
12. [📊 Performance & Optimization](#-performance--optimization)
13. [🐳 Docker Deployment](#-docker-deployment)
14. [🚨 Troubleshooting](#-troubleshooting)
15. [🤝 Contributing](#-contributing)
16. [📄 License](#-license)

---

## 🌟 Overview

**Hypersend** is a production-ready platform that enables:

- **Secure File Transfers**: Support for files up to 40GB+ with chunked upload/download
- **Real-Time Messaging**: WebSocket-based chat with group support
- **P2P Communication**: Direct peer-to-peer file sharing between users
- **Enterprise Security**: JWT authentication, encrypted transfers, CORS protection
- **Cross-Platform**: Flutter mobile app, web frontend (React/Flutter Web), and REST API
- **Scalable Architecture**: Docker-based deployment with load balancing via Nginx
- **Developer-Friendly**: Comprehensive API documentation and testing suite

### 🎯 Primary Use Cases

- Secure file sharing within organizations
- Real-time team communication and collaboration
- Large file transfer with resume capability
- P2P encrypted messaging and file exchange
- Content delivery with tracking and analytics

---

## ✨ Key Features

### 📁 Advanced File Management

| Feature | Description |
|---------|-------------|
| **Chunked Upload System** | Intelligent 8MB chunks (adaptive sizing) |
| **Large File Support** | Handles files up to 40GB+ |
| **Resume Capability** | Interrupted uploads can be resumed |
| **MIME Type Validation** | Comprehensive file type checking |
| **Concurrent Processing** | Parallel chunk upload/download |
| **File Compression** | Automatic compression for certain file types |
| **Deletion Scheduling** | Automatic cleanup of old/unused files |

### 💬 Communication Features

| Feature | Description |
|---------|-------------|
| **Real-Time Chat** | WebSocket-based instant messaging |
| **Group Messaging** | Create and manage group conversations |
| **Message History** | Persistent storage with search capability |
| **Media Sharing** | Share files directly within conversations |
| **P2P Direct Transfer** | User-to-user encrypted file exchange |
| **Typing Indicators** | Show when users are typing |
| **Read Receipts** | Track message delivery and read status |

### 🔐 Security & Authentication

| Feature | Description |
|---------|-------------|
| **JWT Authentication** | Token-based secure authentication |
| **480-Hour Sessions** | Extended sessions for large file uploads |
| **Refresh Tokens** | Automatic token renewal mechanism |
| **Password Hashing** | bcrypt with salt for password storage |
| **Role-Based Access Control** | Granular permission system |
| **CORS Protection** | Configurable origin restrictions |
| **Helmet Security Headers** | Comprehensive HTTP security headers |
| **Input Validation** | Pydantic-based request validation |

### ⚡ Error Handling & Reliability

| Feature | Description |
|---------|-------------|
| **Comprehensive HTTP Coverage** | 300, 400, 500, 600 series error codes |
| **Detailed Error Messages** | Structured responses with helpful hints |
| **Graceful Degradation** | Fallback mechanisms for failures |
| **Debug Mode** | Enhanced error details in development |
| **Error Analytics** | Comprehensive logging and monitoring |
| **Connection Retry Logic** | Automatic reconnection for WebSocket |

### 🚀 Performance Optimization

| Feature | Description |
|---------|-------------|
| **Dynamic Chunking** | Adaptive sizes based on file size |
| **Memory Management** | Streaming for large files |
| **Database Indexing** | Optimized MongoDB queries |
| **Connection Pooling** | Efficient database connections |
| **Redis Caching** | Cache frequently accessed data |
| **Nginx Reverse Proxy** | Load balancing and compression |
| **Async/Await Architecture** | Non-blocking I/O operations |

---

## 🏗️ Architecture

### System Architecture Diagram

```
┌──────────────────────────────────────────────────────────────┐
│                     FRONTEND LAYER                            │
├──────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐        │
│  │ Flutter Web  │  │   React SPA   │  │   Mobile     │        │
│  │   (Browser)  │  │  (Browser)    │  │   App        │        │
│  └──────┬───────┘  └──────┬────────┘  └──────┬───────┘        │
└─────────┼──────────────────┼──────────────────┼──────────────┘
          │                  │                  │
          └──────────────────┼──────────────────┘
                             │ HTTP/WebSocket
┌────────────────────────────┼──────────────────────────────────┐
│                  NGINX REVERSE PROXY                           │
│  • SSL/TLS Termination  • Load Balancing  • Caching            │
└────────────────────────────┼──────────────────────────────────┘
                             │
┌────────────────────────────┼──────────────────────────────────┐
│                   BACKEND API LAYER                            │
├────────────────────────────┼──────────────────────────────────┤
│   ┌─────────────────────────────────────────────────────────┐ │
│   │  FastAPI Application (Uvicorn ASGI)                    │ │
│   │  ┌──────────────────────────────────────────────────┐  │ │
│   │  │          Route Handlers (11 modules)             │  │ │
│   │  │  • Auth Routes  • File Routes  • Chat Routes      │  │ │
│   │  │  • P2P Transfer • Groups       • Messages         │  │ │
│   │  │  • Channels     • Updates      • Users            │  │ │
│   │  └──────────────────────────────────────────────────┘  │ │
│   │  ┌──────────────────────────────────────────────────┐  │ │
│   │  │       Middleware & Error Handlers               │  │ │
│   │  │  • CORS Middleware  • Auth Middleware            │  │ │
│   │  │  • Logging          • Error Handlers             │  │ │
│   │  └──────────────────────────────────────────────────┘  │ │
│   └─────────────────────────────────────────────────────────┘ │
└────────────────────┬─────────────────────────────────────────┘
                     │
        ┌────────────┼────────────┐
        │            │            │
┌───────▼─────┐ ┌────▼────┐ ┌────▼────────┐
│  MongoDB    │ │  Redis  │ │ File Storage │
│  Database   │ │  Cache  │ │ (Local/CDN)  │
└─────────────┘ └─────────┘ └──────────────┘
```

### Data Flow Architecture

```
1. CLIENT REQUEST
   ↓
2. NGINX (Routing & SSL)
   ↓
3. FASTAPI (Authentication & Validation)
   ↓
4. ROUTE HANDLER (Business Logic)
   ├─→ Database Operations (MongoDB)
   ├─→ Cache Lookup (Redis)
   └─→ File Operations
   ↓
5. RESPONSE
   ├─→ JSON Response
   ├─→ File Download
   └─→ WebSocket Event
```

---

## 🛠️ Technology Stack

### Backend Technologies

| Component | Technology | Version | Purpose |
|-----------|-----------|---------|---------|
| **Framework** | FastAPI | 0.115.5 | REST API & WebSocket |
| **Server** | Uvicorn | 0.32.1 | ASGI Server |
| **Database** | MongoDB | 7.0+ | Document storage |
| **Database Driver** | Motor | 3.6.0 | Async MongoDB driver |
| **Validation** | Pydantic | 2.11.5 | Data validation |
| **Authentication** | PyJWT | 2.10.1 | JWT token handling |
| **Hashing** | bcrypt | 4.2.1 | Password hashing |
| **File Handling** | aiofiles | 24.1.0 | Async file operations |
| **Environment** | python-dotenv | 1.0.1 | Environment config |

### Frontend Technologies

| Component | Technology | Version | Purpose |
|-----------|-----------|---------|---------|
| **Mobile App** | Flutter | 3.9+ | Cross-platform UI |
| **State Management** | Flutter BLoC | 8.1.6+ | State management |
| **Routing** | GoRouter | 14.6.2+ | Navigation |
| **HTTP Client** | Dio | 5.7.0+ | API communication |
| **UI Package** | Zaply | Custom | Custom UI components |

### Infrastructure

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Containerization** | Docker | Application containerization |
| **Orchestration** | Docker Compose | Multi-container management |
| **Reverse Proxy** | Nginx | Load balancing & SSL |
| **SSL/TLS** | Let's Encrypt | HTTPS certificates |
| **Caching** | Redis | In-memory caching (optional) |

### Development Tools

| Tool | Version | Purpose |
|------|---------|---------|
| **Python** | 3.11+ | Backend runtime |
| **Node.js** | 16+ | Frontend build tools (if needed) |
| **Git** | Latest | Version control |
| **VS Code** | Latest | Development IDE |

---

## 📦 Project Structure

```
hypersend/
├── 📄 README.md                    # Original project documentation
├── 📄 README_COMPREHENSIVE.md      # This comprehensive guide
├── 🐳 docker-compose.yml           # Multi-container setup
├── ⚙️ nginx.conf                   # Nginx configuration
├── 📋 pyproject.toml               # Python project metadata
│
├── 📁 backend/                     # FastAPI Backend Application
│   ├── 🐍 main.py                  # Application entry point
│   ├── ⚙️ config.py                # Configuration & settings
│   ├── 🔐 security.py              # Security utilities
│   ├── 📊 database.py              # Database connection
│   ├── 🗄️ db_proxy.py              # Database proxy utilities
│   ├── 📝 models.py                # Pydantic data models
│   ├── ✓ validators.py             # Input validation logic
│   ├── 🚨 error_handlers.py        # Error handling middleware
│   ├── ⏱️ rate_limiter.py          # Rate limiting logic
│   ├── 📜 mongo_init.py            # MongoDB initialization
│   ├── 🐳 Dockerfile               # Backend container config
│   ├── 📦 requirements.txt          # Python dependencies
│   │
│   ├── 📁 auth/                    # Authentication module
│   │   ├── dependencies.py         # Auth dependency injections
│   │   ├── jwt_handler.py          # JWT token operations
│   │   ├── password_utils.py       # Password hashing/verification
│   │   └── permissions.py          # Permission checking
│   │
│   ├── 📁 data/                    # Data models & serializers
│   │   ├── schemas.py              # Request/Response schemas
│   │   ├── dto.py                  # Data transfer objects
│   │   └── mappers.py              # Data mapping utilities
│   │
│   ├── 📁 routes/                  # API Route handlers
│   │   ├── auth.py                 # Authentication endpoints
│   │   ├── files.py                # File upload/download endpoints
│   │   ├── chats.py                # Chat endpoints
│   │   ├── messages.py             # Message endpoints
│   │   ├── groups.py               # Group management endpoints
│   │   ├── channels.py             # Channel endpoints
│   │   ├── p2p_transfer.py         # P2P file transfer
│   │   ├── users.py                # User management endpoints
│   │   ├── updates.py              # Real-time updates
│   │   ├── debug.py                # Debug endpoints
│   │   └── __init__.py             # Route registration
│   │
│   └── 📁 utils/                   # Utility modules
│       ├── file_utils.py           # File operations
│       ├── validators.py           # Validation helpers
│       ├── logger.py               # Logging configuration
│       └── helpers.py              # General utilities
│
├── 📁 frontend/                    # Flutter Frontend Application
│   ├── 📄 pubspec.yaml             # Flutter dependencies
│   ├── 📄 analysis_options.yaml    # Dart analysis config
│   ├── 🐳 Dockerfile               # Frontend container config
│   ├── README.md                   # Frontend documentation
│   │
│   ├── 📁 lib/                     # Flutter source code
│   │   ├── main.dart               # App entry point
│   │   ├── 📁 screens/             # UI screens
│   │   ├── 📁 widgets/             # Reusable widgets
│   │   ├── 📁 services/            # Business logic services
│   │   ├── 📁 models/              # Data models
│   │   └── 📁 utils/               # Utilities
│   │
│   ├── 📁 assets/                  # Images, icons, fonts
│   └── 📁 web/                     # Web-specific files
│
├── 📁 build/                       # Build artifacts
│   ├── CMakeFiles/                 # CMake build files
│   ├── Debug/                      # Debug build output
│   └── runner.sln                  # Visual Studio solution
│
├── 📁 data/                        # Data storage (Docker volumes)
│   ├── db/                         # MongoDB data directory
│   ├── files/                      # Uploaded files
│   ├── tmp/                        # Temporary files
│   └── uploads/                    # Processing uploads
│
├── 📁 scripts/                     # Utility scripts
│   ├── seed_mongodb.py             # Database seeding
│   ├── run_testsprite_mcp.js       # Test runner
│   └── 📁 testsprite_tests/        # Test suite
│
├── 📁 tests/                       # Comprehensive test suite
│   ├── test_auth_*.py              # Authentication tests
│   ├── test_files*.py              # File operation tests
│   ├── test_comprehensive_*.py     # Integration tests
│   ├── FINAL_TEST_FIXES_SUMMARY.md # Test documentation
│   └── ... (50+ test files)
│
├── 📁 docs/                        # Documentation
│   └── (API docs, guides, etc.)
│
└── 📁 assets/                      # Project assets
    ├── logos/
    └── icons/
```

### Module Descriptions

#### **Backend Routes** (`routes/`)

| Module | Endpoints | Purpose |
|--------|-----------|---------|
| `auth.py` | Register, Login, Refresh Token | User authentication |
| `files.py` | Upload, Download, Delete | File management |
| `chats.py` | Create, Get, List | Chat management |
| `messages.py` | Send, Edit, Delete | Message handling |
| `groups.py` | Create, Add Member, Remove | Group management |
| `channels.py` | Create, Subscribe, Publish | Channel operations |
| `p2p_transfer.py` | Initiate, Accept, Transfer | P2P file sharing |
| `users.py` | Profile, Settings, Search | User management |
| `updates.py` | WebSocket, Events | Real-time updates |
| `debug.py` | Health, Status, Logs | Debug endpoints |

---

## ⚙️ Installation & Setup

### Prerequisites

- **Python**: 3.11 or higher
- **Docker & Docker Compose**: Latest version
- **MongoDB**: 7.0+ (via Docker or Atlas)
- **Git**: For version control
- **4GB RAM** minimum (8GB recommended)
- **10GB Storage** for test data

### Step 1: Clone the Repository

```bash
git clone https://github.com/Mayankvlog/Hypersend.git
cd hypersend
```

### Step 2: Environment Configuration

Create a `.env` file in the project root:

```bash
# MongoDB Configuration
MONGO_USER=hypersend
MONGO_PASSWORD=hypersend_secure_password
MONGO_HOST=mongo
MONGO_PORT=27017
MONGO_INITDB_DATABASE=hypersend
MONGODB_URI=mongodb://hypersend:hypersend_secure_password@mongo:27017/hypersend

# FastAPI Configuration
API_HOST=0.0.0.0
API_PORT=8000
API_BASE_URL=http://localhost:8000

# Security
SECRET_KEY=your_super_secret_key_change_this_in_production
JWT_EXPIRATION_MINUTES=480
ALGORITHM=HS256

# CORS Configuration
CORS_ORIGINS=["http://localhost:3000","http://localhost:8080","http://localhost"]
CORS_CREDENTIALS=true
CORS_METHODS=["*"]
CORS_HEADERS=["*"]

# File Configuration
MAX_FILE_SIZE=42949672960  # 40GB
CHUNK_SIZE=8388608        # 8MB
UPLOAD_TIMEOUT=3600       # 1 hour

# Debug Mode
DEBUG=true
LOG_LEVEL=INFO

# Optional: Redis Configuration
REDIS_URL=redis://redis:6379
REDIS_DB=0

# Domain Configuration
DOMAIN=zaply.in.net
```

### Step 3: Install Python Dependencies

#### Option A: Using pip (Development)

```bash
# Create virtual environment
python -m venv venv
source venv/Scripts/activate  # On Windows
# source venv/bin/activate     # On macOS/Linux

# Install dependencies
pip install -r backend/requirements.txt
```

#### Option B: Using Docker (Recommended)

Docker will handle all dependencies automatically.

### Step 4: Backend Setup (Non-Docker)

If running without Docker, start MongoDB first:

```bash
# Option 1: Local MongoDB (if installed)
mongod

# Option 2: Docker MongoDB only
docker run -d \
  -e MONGO_INITDB_ROOT_USERNAME=root \
  -e MONGO_INITDB_ROOT_PASSWORD=password \
  -p 27017:27017 \
  mongo:latest
```

---

## 🚀 Running the Application

### Option 1: Docker Compose (Recommended)

```bash
# Build and start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down

# Clean up everything (including volumes)
docker-compose down -v
```

### Option 2: Development Mode (Without Docker)

```bash
# Terminal 1: Start MongoDB
mongod

# Terminal 2: Start FastAPI Backend
cd backend
python main.py

# Terminal 3: Start Flutter Frontend (optional)
cd frontend
flutter run -d chrome  # For web
# or
flutter run -d emulator  # For mobile emulator
```

### Option 3: Production Deployment

```bash
# Build production images
docker-compose -f docker-compose.yml build

# Deploy with environment variables
export SECRET_KEY=your_production_secret_key
docker-compose -f docker-compose.yml up -d

# Check health
curl http://localhost/health
```

---

## 🔧 Configuration

### MongoDB Configuration

Update `backend/config.py`:

```python
# Local development
MONGODB_URI = "mongodb://localhost:27017/hypersend"

# MongoDB Atlas (Cloud)
MONGODB_URI = "mongodb+srv://user:password@cluster.mongodb.net/hypersend"

# Docker Compose
MONGODB_URI = "mongodb://hypersend:password@mongo:27017/hypersend"
```

### Security Configuration

Edit `backend/config.py` or `.env`:

```python
# JWT Configuration
JWT_EXPIRATION_MINUTES = 480  # 8 hours
JWT_REFRESH_EXPIRATION_DAYS = 7
ALGORITHM = "HS256"

# Password Security
PASSWORD_MIN_LENGTH = 8
HASH_ITERATIONS = 100000

# CORS Configuration
CORS_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:8080",
    "https://yourdomain.com"
]
```

### File Upload Configuration

```python
# Maximum file size (40GB)
MAX_FILE_SIZE = 42949672960

# Chunk size (8MB)
CHUNK_SIZE = 8388608

# Upload timeout (1 hour)
UPLOAD_TIMEOUT = 3600

# Allowed MIME types
ALLOWED_MIME_TYPES = [
    "application/pdf",
    "image/*",
    "video/*",
    "audio/*",
    "application/*"
]
```

---

## 📚 API Documentation

### Interactive Documentation

Once the backend is running, visit:

- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`
- **OpenAPI JSON**: `http://localhost:8000/openapi.json`

### Core API Endpoints

#### Authentication Routes (`/api/v1/auth`)

```http
POST   /auth/register           # Create new user account
POST   /auth/login              # Login with credentials
POST   /auth/refresh            # Refresh JWT token
POST   /auth/logout             # Logout (invalidate token)
GET    /auth/me                 # Get current user profile
PUT    /auth/change-password    # Change user password
```

**Example: Register**
```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "email": "john@example.com",
    "password": "SecurePass123!"
  }'
```

**Response (200 OK)**
```json
{
  "id": "507f1f77bcf86cd799439011",
  "username": "john_doe",
  "email": "john@example.com",
  "access_token": "eyJhbGc...",
  "token_type": "bearer",
  "expires_in": 28800
}
```

#### File Routes (`/api/v1/files`)

```http
POST   /files/upload/init       # Initiate chunked upload
POST   /files/upload/chunk      # Upload file chunk
POST   /files/upload/complete   # Complete upload
GET    /files/{file_id}         # Download file
GET    /files/list              # List user files
DELETE /files/{file_id}         # Delete file
```

**Example: Upload Large File**
```bash
# 1. Initiate upload
curl -X POST http://localhost:8000/api/v1/files/upload/init \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "filename": "large_video.mp4",
    "file_size": 5368709120,
    "content_type": "video/mp4"
  }'

# Response contains: upload_id, chunk_count, chunk_size

# 2. Upload chunks (repeat for each chunk)
curl -X POST http://localhost:8000/api/v1/files/upload/chunk \
  -H "Authorization: Bearer TOKEN" \
  -F "upload_id=abc123" \
  -F "chunk_number=0" \
  -F "chunk=@chunk_0.bin"

# 3. Complete upload
curl -X POST http://localhost:8000/api/v1/files/upload/complete \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"upload_id": "abc123"}'
```

#### Chat Routes (`/api/v1/chats`)

```http
POST   /chats                   # Create new chat
GET    /chats                   # List user chats
GET    /chats/{chat_id}         # Get chat details
PUT    /chats/{chat_id}         # Update chat
DELETE /chats/{chat_id}         # Delete chat
POST   /chats/{chat_id}/leave   # Leave chat
```

#### Message Routes (`/api/v1/messages`)

```http
POST   /messages                # Send message
GET    /messages/{chat_id}      # Get chat messages
PUT    /messages/{msg_id}       # Edit message
DELETE /messages/{msg_id}       # Delete message
POST   /messages/{msg_id}/react # Add reaction
```

#### WebSocket Connection (`/ws/{user_id}`)

```javascript
// Connect to WebSocket
const ws = new WebSocket('ws://localhost:8000/ws/user123?token=JWT_TOKEN');

// Listen for events
ws.onmessage = (event) => {
  const message = JSON.parse(event.data);
  console.log('Received:', message);
};

// Send message
ws.send(JSON.stringify({
  type: 'chat_message',
  chat_id: 'chat123',
  content: 'Hello, world!'
}));
```

#### P2P Transfer Routes (`/api/v1/p2p`)

```http
POST   /p2p/initiate            # Start P2P transfer
POST   /p2p/{transfer_id}/accept # Accept transfer
POST   /p2p/{transfer_id}/reject # Reject transfer
GET    /p2p/history             # Get transfer history
```

#### User Routes (`/api/v1/users`)

```http
GET    /users/{user_id}         # Get user profile
PUT    /users/{user_id}         # Update profile
GET    /users/search            # Search users
POST   /users/{user_id}/follow  # Follow user
DELETE /users/{user_id}/follow  # Unfollow user
```

---

## 🧪 Testing

### Test Suite Overview

The project includes **50+ comprehensive test files** covering:

- **Authentication**: Login, registration, token refresh
- **File Operations**: Upload, download, chunking
- **Messaging**: Chat, groups, real-time updates
- **Error Handling**: 4xx, 5xx, 6xx error scenarios
- **Security**: Input validation, SQL injection prevention
- **Performance**: Load testing, concurrent operations

### Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test file
python -m pytest tests/test_auth_routes.py -v

# Run tests with coverage
python -m pytest tests/ --cov=backend --cov-report=html

# Run tests matching pattern
python -m pytest tests/test_files*.py -v

# Run with verbose output and stop on first failure
python -m pytest tests/ -vvx
```

### Key Test Files

| File | Purpose |
|------|---------|
| `test_auth_routes.py` | Authentication endpoints |
| `test_file_operations.py` | File upload/download |
| `test_comprehensive_validation.py` | Input validation |
| `COMPREHENSIVE_SECURITY_AUDIT.py` | Security testing |
| `test_all_fixes.py` | Integration tests |

---

## 🔒 Security Features

### Authentication & Authorization

```python
# JWT Token Flow
1. User login → Server generates JWT token
2. Token contains: user_id, exp, iat, scopes
3. Client includes token in Authorization header
4. Server validates token signature
5. Token expires after 480 hours (configurable)
6. User can refresh token before expiration
```

### Password Security

- **Hashing**: bcrypt with salt (100,000 iterations)
- **Min Length**: 8 characters
- **Complexity**: Optional strength validation
- **Reset**: Secure token-based password reset

### Data Protection

```python
# File Encryption (Optional)
# - Implement AES-256 encryption for sensitive files
# - Store encryption keys in secure vault
# - Implement zero-knowledge encryption

# Database Security
# - Use encrypted connections (TLS)
# - Implement field-level encryption for sensitive data
# - Regular backups with encryption
```

### API Security

```python
# CORS Configuration
CORS_ORIGINS = ["https://trusted.domain.com"]  # Restrict origins
CORS_CREDENTIALS = True                         # Require credentials
CORS_METHODS = ["GET", "POST", "PUT", "DELETE"] # Limit methods

# Rate Limiting
# - Implement per-user rate limits
# - Implement per-IP rate limits
# - Implement exponential backoff for failed auth

# Input Validation
# - Pydantic models validate all inputs
# - File type validation
# - Size validation
# - Filename sanitization
```

### Deployment Security

- **HTTPS/TLS**: Enforced via Nginx
- **HSTS**: HTTP Strict Transport Security
- **CSP**: Content Security Policy headers
- **X-Frame-Options**: Clickjacking protection
- **X-Content-Type-Options**: MIME type sniffing prevention

---

## 📊 Performance & Optimization

### Chunked File Transfer

```
File: 5GB
Chunk Size: 8MB
Chunks: 655

Upload Process:
1. Client chunks file (8MB per chunk)
2. Each chunk uploaded concurrently
3. Server stores chunks temporarily
4. After all chunks received, server assembles file
5. Temporary chunks deleted
6. File stored permanently

Benefits:
✓ Resume capability
✓ Reduced memory usage
✓ Better bandwidth utilization
✓ Progress tracking
✓ Parallel processing
```

### Database Optimization

```python
# MongoDB Indexing
db.chats.create_index([("user_id", 1), ("created_at", -1)])
db.messages.create_index([("chat_id", 1), ("created_at", -1)])
db.files.create_index([("user_id", 1), ("created_at", -1)])
db.users.create_index([("email", 1)])
db.users.create_index([("username", 1)])

# Connection Pooling
max_pool_size = 50
min_pool_size = 10
```

### Caching Strategy

```python
# Redis Caching
- User profiles (5 min TTL)
- Chat metadata (10 min TTL)
- File metadata (1 hour TTL)
- JWT token blacklist (persistent)

# Application Caching
- In-memory caching for frequently accessed data
- Query result caching
- File metadata caching
```

### Async/Await Architecture

```python
# All I/O operations are non-blocking
✓ Database queries use Motor (async)
✓ File operations use aiofiles (async)
✓ HTTP requests use httpx (async)
✓ WebSocket connections are async
✓ No blocking operations in request handlers
```

---

## 🐳 Docker Deployment

### Docker Compose Services

```yaml
Services:
1. nginx          - Reverse proxy, SSL, static files
2. backend        - FastAPI application server
3. frontend       - Flutter Web application
4. mongo          - MongoDB database
5. mongo-express  - MongoDB admin interface (optional)
6. redis          - Caching layer (optional)
```

### Docker Compose Commands

```bash
# Start services
docker-compose up -d

# View logs
docker-compose logs -f backend
docker-compose logs -f mongo

# Check service status
docker-compose ps

# Restart service
docker-compose restart backend

# Stop services
docker-compose stop

# Remove everything
docker-compose down
docker-compose down -v  # Also remove volumes

# Rebuild images
docker-compose build --no-cache
```

### Production Deployment Checklist

- [ ] Set production SECRET_KEY
- [ ] Configure CORS_ORIGINS for your domain
- [ ] Set DEBUG=false
- [ ] Configure MongoDB with authentication
- [ ] Set up SSL certificates (Let's Encrypt)
- [ ] Configure backup strategy
- [ ] Set up monitoring and logging
- [ ] Enable rate limiting
- [ ] Configure database connection pooling
- [ ] Set up CDN for file delivery
- [ ] Configure health checks
- [ ] Set up automatic restarts

---

## 🚨 Troubleshooting

### Common Issues & Solutions

#### 1. MongoDB Connection Failed

```
Error: "Connection refused" or "Authentication failed"

Solution:
1. Check MongoDB is running: docker-compose ps mongo
2. Verify credentials in .env file
3. Check MongoDB URI: MONGODB_URI
4. Restart MongoDB: docker-compose restart mongo
5. Check MongoDB logs: docker-compose logs mongo
```

#### 2. JWT Token Invalid

```
Error: "Could not validate credentials"

Solution:
1. Verify SECRET_KEY matches in .env
2. Check token hasn't expired
3. Check Authorization header format: "Bearer TOKEN"
4. Verify token hasn't been tampered with
5. Check JWT_EXPIRATION_MINUTES setting
```

#### 3. File Upload Fails

```
Error: "413 Payload Too Large" or timeout

Solution:
1. Increase Nginx client_max_body_size in nginx.conf
2. Increase UPLOAD_TIMEOUT in config
3. Verify chunk size: CHUNK_SIZE setting
4. Check available disk space
5. Check file permissions in /data/uploads
```

#### 4. WebSocket Connection Failed

```
Error: "WebSocket connection closed"

Solution:
1. Verify WebSocket URL format: ws://host/ws/user_id
2. Check Authentication header is included
3. Verify Nginx WebSocket proxying is configured
4. Check CORS settings allow WebSocket origins
5. Check server logs for connection errors
```

#### 5. Frontend Can't Reach Backend

```
Error: CORS error or "Network error"

Solution:
1. Check backend is running: curl http://localhost:8000
2. Verify CORS_ORIGINS in config includes frontend origin
3. Check frontend API_BASE_URL is correct
4. Verify Nginx is forwarding requests correctly
5. Check firewall isn't blocking requests
```

#### 6. Slow File Upload/Download

```
Solution:
1. Check chunk size: CHUNK_SIZE setting
2. Enable compression in Nginx
3. Check database performance: add indexes
4. Monitor CPU/Memory usage
5. Check network speed: iperf test
6. Consider enabling CDN for file delivery
```

### Debug Commands

```bash
# Check backend health
curl http://localhost:8000/health

# Test authentication
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test"}'

# View backend logs
docker-compose logs -f backend

# View MongoDB logs
docker-compose logs -f mongo

# Check MongoDB database
docker-compose exec mongo mongosh -u root -p password

# Run tests
python -m pytest tests/ -v --tb=short

# Check open ports
netstat -tulpn | grep LISTEN

# Check Docker network
docker network inspect hypersend_network
```

---

## 🤝 Contributing

We welcome contributions! Please follow these guidelines:

### Development Workflow

```bash
# 1. Fork the repository
git clone https://github.com/yourusername/Hypersend.git
cd hypersend

# 2. Create feature branch
git checkout -b feature/amazing-feature

# 3. Make changes and commit
git add .
git commit -m "Add amazing feature"

# 4. Push to branch
git push origin feature/amazing-feature

# 5. Create Pull Request
```

### Code Standards

- **Python**: PEP 8 compliant
- **Type Hints**: Use type annotations
- **Documentation**: Add docstrings to functions
- **Testing**: Write tests for new features
- **Commits**: Use descriptive commit messages

### Pull Request Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests added
- [ ] Integration tests added
- [ ] Manual testing done

## Checklist
- [ ] Code follows style guidelines
- [ ] Documentation updated
- [ ] No new warnings generated
- [ ] Tests pass locally
```

---

## 📄 License

This project is licensed under the **MIT License** - see the LICENSE file for details.

```
MIT License

Copyright (c) 2024 Mayank Khurana

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions...
```

---

## 📞 Support & Contact

- **Author**: Mayank Khurana
- **Email**: mayank.kr0311@gmail.com
- **GitHub**: [Mayankvlog](https://github.com/Mayankvlog)
- **Issues**: [GitHub Issues](https://github.com/Mayankvlog/Hypersend/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Mayankvlog/Hypersend/discussions)

---

## 🗺️ Roadmap

### v1.0 (Current)
- ✅ File upload/download with chunking
- ✅ Real-time messaging
- ✅ User authentication
- ✅ Group chats
- ✅ P2P transfers

### v1.1 (Planned)
- 🔜 End-to-end encryption
- 🔜 Message reactions
- 🔜 Voice/video calls
- 🔜 Message search
- 🔜 File previews

### v2.0 (Future)
- 🔜 Mobile app optimization
- 🔜 Offline support
- 🔜 Advanced analytics
- 🔜 Custom themes
- 🔜 Plugin system

---

## 🙏 Acknowledgments

- Built with [FastAPI](https://fastapi.tiangolo.com/)
- Database by [MongoDB](https://www.mongodb.com/)
- Frontend with [Flutter](https://flutter.dev/)
- Containerized with [Docker](https://www.docker.com/)

---

**Last Updated**: January 2024  
**Version**: 1.0.0  
**Status**: ✅ Production Ready
