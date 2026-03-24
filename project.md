# Hypersend (Zaply)

**A secure, fast, and modern P2P chat and file transfer application with end-to-end encryption**

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-Production%20Ready-brightgreen)

---

## Overview

Hypersend (branded as Zaply) is a comprehensive P2P chat and file transfer platform that prioritizes security, speed, and user experience. It enables users to communicate in real-time, share files efficiently (up to 15GB per file), and manage their digital identity across multiple devices with end-to-end encryption.

The application consists of:
- **Backend API**: FastAPI-based REST/WebSocket server with MongoDB and Redis
- **Cross-Platform Frontend**: Flutter application for iOS, Android, Web, Windows, Linux, and macOS
- **Infrastructure**: Docker containerized deployment with Nginx reverse proxy

---

## Key Features

### Communication
- End-to-End Encryption (E2EE) using Signal Protocol
- Real-time messaging via WebSocket
- Group chats with admin management
- Multi-device support (same account across devices)
- Message history with search capabilities
- Online/offline presence tracking

### File Sharing
- Large file support (up to 15GB per file)
- Chunked upload/download for efficient transfers
- Server-side file encryption
- Bandwidth management with rate limiting

### Security
- JWT-based authentication with refresh tokens
- Bcrypt password hashing
- Rate limiting (DDoS protection)
- HTTPS/TLS in production
- Comprehensive input validation

---

## Technology Stack

### Backend
| Component | Technology |
|-----------|-----------|
| Framework | FastAPI 0.115.5 |
| Server | Uvicorn 0.32.1 |
| Database | MongoDB Atlas |
| Cache | Redis 7.2 |
| ORM | Motor 3.6.0 (Async MongoDB) |
| Authentication | PyJWT + python-jose |
| Cryptography | PyNaCl, cryptography |
| Validation | Pydantic 2.11.5 |
| Language | Python 3.11+ |

### Frontend
| Component | Technology |
|-----------|-----------|
| Framework | Flutter 3.9.2+ |
| Language | Dart 3.9.2+ |
| State Management | BLoC Pattern |
| HTTP Client | Dio |
| Platforms | iOS, Android, Web, Windows, Linux, macOS |

### Infrastructure
- **Reverse Proxy**: Nginx (SSL termination, routing)
- **Containerization**: Docker + Docker Compose
- **SSL**: Let's Encrypt + Certbot
- **Domain**: zaply.in.net

---

## Architecture

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
│            Nginx Reverse Proxy (Port 443)            │
│  ┌───────────────────────────────────────────────┐  │
│  │ - SSL/TLS Termination, Request Routing        │  │
│  │ - Compression, Cache Management                │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
                  │
    ┌─────────────┴─────────────┐
    │      Backend API         │
    │       (FastAPI)           │
    └─────────────┬─────────────┘
                  │
      ┌───────────┼───────────┐
      │           │           │
  ┌───▼───┐   ┌───▼───┐   ┌──▼────┐
  │MongoDB│   │ Redis │   │  S3   │
  │ Atlas │   │ Cache │   │Storage│
  └───────┘   └───────┘   └───────┘
```

---

## Project Structure

```
hypersend/
├── backend/                    # FastAPI Backend
│   ├── auth/                   # Authentication & Authorization
│   ├── crypto/                 # E2EE Cryptography (Signal Protocol)
│   ├── routes/                 # API Endpoints (auth, chats, messages, files, etc.)
│   ├── services/               # Business Logic
│   ├── websocket/             # WebSocket Management
│   ├── workers/                # Async Workers
│   ├── main.py                # FastAPI Application Entry
│   ├── database.py            # Database Connection
│   ├── config.py              # Configuration
│   └── error_handlers.py      # Exception Handling
│
├── frontend/                   # Flutter Application
│   ├── lib/                    # Dart source code
│   │   ├── core/              # Constants, router, theme
│   │   ├── data/              # Models, repositories
│   │   ├── logic/             # BLoC state management
│   │   └── presentation/      # Screens, widgets
│   └── pubspec.yaml           # Flutter dependencies
│
├── docker-compose.yml          # Multi-container orchestration
├── nginx.conf                  # Nginx configuration
├── kubernetes.yaml             # Kubernetes deployment
└── pyproject.toml              # Python project metadata
```

---

## API Endpoints

### Authentication
```
POST   /api/v1/auth/register       # Register new user
POST   /api/v1/auth/login          # Login
POST   /api/v1/auth/refresh        # Refresh token
POST   /api/v1/auth/forgot-password
POST   /api/v1/auth/reset-password
```

### Users
```
GET    /api/v1/users/me            # Get current user
PUT    /api/v1/users/me            # Update profile
GET    /api/v1/users/search        # Search users
```

### Chats & Messages
```
GET    /api/v1/chats               # List chats
POST   /api/v1/chats               # Create chat
GET    /api/v1/chats/{id}/messages # Get messages
POST   /api/v1/chats/{id}/messages # Send message
```

### Files
```
POST   /api/v1/attach/photos-videos/init   # Initialize upload
PUT    /api/v1/files/{id}/chunk            # Upload chunk
POST   /api/v1/files/{id}/complete         # Complete upload
GET    /api/v1/files/{id}                  # Download file
```

### WebSocket
```
WS     /api/v1/ws                  # Real-time messaging
```

---

## Configuration

### Environment Variables
```bash
# Database
MONGODB_URI=mongodb+srv://...
DATABASE_NAME=Hypersend

# Security
SECRET_KEY=your_secret_key
JWT_SECRET_KEY=your_jwt_secret

# File Storage
MAX_FILE_SIZE_BYTES=16106127360  # 15GB
CHUNK_SIZE=4194304              # 4MB

# Redis
REDIS_URL=redis://localhost:6379/0

# API
ALLOWED_ORIGINS=https://zaply.in.net
```

---

## Running the Application

### Docker Compose (Recommended)
```bash
docker-compose up --build
```

### Local Development
```bash
# Backend
cd backend
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Frontend
cd frontend
flutter pub get
flutter run -d chrome
```

---

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=backend --cov-report=html
```

---

## License

MIT License - See [LICENSE](LICENSE) file for details.

---

## Contact

- **Email**: mayank.kr0311@gmail.com
- **Website**: https://zaply.in.net
- **GitHub**: https://github.com/yourusername/hypersend

---

**Made with ❤️ by Mayank** | Version: 1.0.0