# 🚀 Hypersend - Fast. Secure. Chat.

A WhatsApp-inspired secure messaging platform with end-to-end encryption, multi-device support, and enterprise-grade file sharing capabilities.

## 📋 Table of Contents

- [🌟 Features](#-features)
- [🏗️ Architecture](#️-architecture)
- [🚀 Quick Start](#-quick-start)
- [📋 Prerequisites](#-prerequisites)
- [🛠️ Installation](#️-installation)
- [⚙️ Configuration](#️-configuration)
- [🐳 Docker Deployment](#-docker-deployment)
- [🌐 Production Deployment](#-production-deployment)
- [📊 API Documentation](#-api-documentation)
- [🧪 Testing](#-testing)
- [🔒 Security](#-security)
- [📱 Frontend](#-frontend)
- [🔧 Backend](#-backend)
- [📈 Monitoring](#-monitoring)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)

## 🌟 Features

### 📱 WhatsApp-Style Messaging
- **End-to-End Encryption**: Signal Protocol implementation
- **Multi-Device Support**: Up to 4 devices per user
- **Real-time Sync**: Message synchronization across all devices
- **Message History**: Encrypted cloud backup with 24-hour TTL
- **Group Chat**: Secure group messaging with admin controls

### 📁 Enterprise File Sharing
- **15GB File Support**: Upload and share large files
- **Chunked Uploads**: Resumable uploads for large files
- **Multi-format Support**: Images, videos, documents, audio
- **Ephemeral Storage**: WhatsApp-style temporary file hosting
- **S3 Integration**: Scalable cloud storage backend

### 🔐 Security & Privacy
- **Zero-Knowledge Architecture**: Server cannot access message content
- **Signal Protocol**: Industry-standard E2EE implementation
- **Perfect Forward Secrecy**: Compromised keys don't affect past messages
- **Device Authentication**: QR code-based device linking
- **Rate Limiting**: Abuse prevention and spam protection

### ⚡ Performance
- **Redis Caching**: Real-time message delivery
- **WebSocket Connections**: Persistent, low-latency communication
- **Horizontal Scaling**: Kubernetes-ready architecture
- **CDN Integration**: Global content delivery
- **Load Balancing**: Nginx reverse proxy with health checks

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   📱 User      │    │   🌐 Nginx     │    │   🔧 Backend   │
│   Devices       │◄──►│   Reverse       │◄──►│   API Server    │
│   (4 max)      │    │   Proxy         │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   🗄️ S3        │    │   📦 Redis     │    │   🗄️ MongoDB   │
│   Storage       │    │   Cache        │    │   Database      │
│   (24h TTL)     │    │   (Ephemeral)  │    │   (Atlas)       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### 📦 Technology Stack

#### **Frontend (Flutter)**
- **Framework**: Flutter 3.9.2+
- **State Management**: BLoC Pattern
- **Networking**: Dio HTTP Client
- **Encryption**: PointyCastle & Encrypt
- **Storage**: Flutter Secure Storage
- **Platforms**: Web, iOS, Android, Linux, Windows

#### **Backend (Python/FastAPI)**
- **Framework**: FastAPI with Uvicorn
- **Authentication**: JWT with refresh tokens
- **Database**: MongoDB Atlas with Redis cache
- **File Storage**: AWS S3 with temporary URLs
- **Encryption**: Signal Protocol implementation
- **WebSocket**: Real-time messaging

#### **Infrastructure (Docker/K8s)**
- **Containerization**: Docker & Docker Compose
- **Reverse Proxy**: Nginx with SSL termination
- **Load Balancing**: Nginx upstream pools
- **Monitoring**: Prometheus + Grafana
- **Deployment**: Kubernetes ready

## 🚀 Quick Start

### 🏃‍♂️ One-Command Deployment
```bash
# Clone and deploy
git clone https://github.com/your-org/hypersend.git
cd hypersend
docker-compose up -d --build

# Access the application
# Frontend: https://zaply.in.net
# API: https://zaply.in.net/api/v1
# Health: https://zaply.in.net/health
```

### 🧪 Development Setup
```bash
# Backend development
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Frontend development
cd frontend
flutter pub get
flutter run -d web  # or flutter run for mobile
```

## 📋 Prerequisites

### 🔧 Development Requirements
- **Python**: 3.9+ with pip
- **Flutter**: 3.9.2+ with Dart SDK
- **Docker**: 20.10+ with Docker Compose
- **Node.js**: 18+ (for Flutter web tools)
- **Git**: For version control

### 🌐 Production Requirements
- **VPS**: 4GB+ RAM, 2+ CPU cores, 50GB+ SSD
- **Domain**: Custom domain with DNS control
- **SSL**: TLS certificate (Let's Encrypt recommended)
- **MongoDB**: Atlas cluster or self-hosted
- **Redis**: 6.0+ for caching
- **S3**: AWS S3 or compatible storage

## 🛠️ Installation

### 📦 Backend Setup
```bash
# Clone repository
git clone https://github.com/your-org/hypersend.git
cd hypersend/backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Environment configuration
cp .env.example .env
nano .env  # Edit with your settings

# Run development server
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### 📱 Frontend Setup
```bash
# Navigate to frontend
cd frontend

# Install Flutter dependencies
flutter pub get

# Run in development mode
flutter run -d web    # Web development
flutter run           # Mobile development

# Build for production
flutter build web    # Web build
flutter build apk    # Android build
flutter build ios    # iOS build
```

## ⚙️ Configuration

### 🔐 Environment Variables

#### **Core Configuration**
```bash
# Domain Settings
DOMAIN_NAME=zaply.in.net
API_BASE_URL=https://zaply.in.net/api/v1

# Security
SECRET_KEY=your-super-secret-jwt-key-here
ALGORITHM=HS256
DEBUG=false

# Database
MONGODB_URI=mongodb+srv://user:pass@cluster.mongodb.net/db
REDIS_HOST=redis
REDIS_PORT=6379
```

#### **Email Configuration**
```bash
# SMTP Settings
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
EMAIL_FROM=noreply@zaply.in.net
SENDER_NAME=Hypersend Support
```

#### **File Storage Configuration**
```bash
# S3 Settings
AWS_ACCESS_KEY_ID=your-aws-access-key
AWS_SECRET_ACCESS_KEY=your-aws-secret-key
AWS_REGION=us-east-1
S3_BUCKET=hypersend-temp

# File Limits
MAX_FILE_SIZE_BYTES=16106127360  # 15GB
CHUNK_SIZE=33554432             # 4MB
FILE_TTL_SECONDS=86400           # 24 hours
```

### 🌐 CORS Configuration
```bash
# Allowed Origins
ALLOWED_ORIGINS=https://zaply.in.net,https://www.zaply.in.net

# Development Origins (optional)
# https://zaply.in.net/
```

## 🐳 Docker Deployment

### 🚀 Production Deployment
```bash
# Clone and prepare
git clone https://github.com/your-org/hypersend.git
cd hypersend

# Configure production environment
cp .env.production .env
nano .env  # Update with your values

# Deploy with Docker Compose
docker-compose up -d --build

# Monitor deployment
docker-compose ps
docker-compose logs -f
```

### 📊 Service Management
```bash
# Start services
docker-compose up -d

# Stop services
docker-compose down

# Update services
docker-compose pull
docker-compose up -d --build

# View logs
docker-compose logs backend
docker-compose logs frontend
docker-compose logs nginx

# Access containers
docker-compose exec backend bash
docker-compose exec redis redis-cli
```

### 🔧 Docker Compose Services
- **nginx**: Reverse proxy with SSL termination
- **backend**: FastAPI application server
- **frontend**: Flutter web application
- **redis**: In-memory cache and session store

## 🌐 Production Deployment

### 🚀 VPS Deployment Steps

#### **1. Server Preparation**
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Add user to docker group
sudo usermod -aG docker $USER
```

#### **2. SSL Certificate Setup**
```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx -y

# Obtain SSL certificate
sudo certbot --nginx -d zaply.in.net -d www.zaply.in.net

# Setup auto-renewal
echo "0 12 * * * /usr/bin/certbot renew --quiet" | sudo crontab -
```

#### **3. Deploy Application**
```bash
# Clone repository
git clone https://github.com/your-org/hypersend.git
cd hypersend

# Configure environment
cp .env.production .env
nano .env  # Update production values

# Deploy
docker-compose up -d --build

# Verify deployment
curl https://zaply.in.net/health
```

### 🔍 Kubernetes Deployment
```bash
# Apply Kubernetes manifests
kubectl apply -f kubernetes.yaml

# Check deployment status
kubectl get pods
kubectl get services

# Access application
kubectl port-forward service/hypersend-frontend 8080:80
```

## 📊 API Documentation

### 🔗 Base URL
```
Production: https://zaply.in.net/api/v1
Development: http://localhost:8000/api/v1
```

### 🔐 Authentication Endpoints
```bash
# User Registration
POST /auth/register
{
  "email": "user@example.com",
  "password": "securepassword",
  "name": "User Name"
}

# User Login
POST /auth/login
{
  "email": "user@example.com", 
  "password": "securepassword"
}

# Token Refresh
POST /auth/refresh
Headers: Authorization: Bearer <refresh_token>
```

### 💬 Messaging Endpoints
```bash
# Send Message
POST /messages/send
Headers: Authorization: Bearer <access_token>
{
  "recipient_id": "user_id",
  "content": "encrypted_message_content",
  "message_type": "text"
}

# Get Messages
GET /messages/{chat_id}
Headers: Authorization: Bearer <access_token>

# WebSocket Connection
WS /ws
Headers: Authorization: Bearer <access_token>
```

### 📁 File Upload Endpoints
```bash
# Initiate Upload
POST /files/upload/init
Headers: Authorization: Bearer <access_token>
{
  "filename": "document.pdf",
  "file_size": 1048576,
  "file_type": "document"
}

# Upload Chunk
POST /files/upload/chunk
Headers: Authorization: Bearer <access_token>
Form Data:
- chunk_id: "upload_id"
- chunk_index: 0
- chunk_data: <binary_data>
```

## 🧪 Testing

### 🧪 Backend Tests
```bash
# Navigate to backend
cd backend

# Run all tests
pytest

# Run specific test file
pytest tests/test_auth.py

# Run with coverage
pytest --cov=. --cov-report=html

# Run security tests
pytest tests/test_security_validation.py
```

### 📱 Frontend Tests
```bash
# Navigate to frontend
cd frontend

# Run unit tests
flutter test

# Run widget tests
flutter test integration_test/

# Analyze code
flutter analyze

# Build for testing
flutter build web --no-sound-null-safety
```

### 🚀 Integration Tests
```bash
# Run full integration suite
cd tests
pytest integration/

# Run API integration tests
pytest tests/test_api_integration.py

# Run end-to-end tests
pytest tests/test_e2e_flow.py
```

## 🔒 Security

### 🛡️ Security Features
- **End-to-End Encryption**: Signal Protocol implementation
- **Perfect Forward Secrecy**: Compromised keys don't affect past messages
- **Device Authentication**: QR code-based secure device linking
- **Rate Limiting**: 100 requests/minute per user
- **Input Validation**: Comprehensive request validation
- **SQL Injection Protection**: ORM-based database queries
- **XSS Protection**: Content Security Policy headers
- **CSRF Protection**: SameSite cookies and CSRF tokens

### 🔐 Security Headers
```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'
```

### 🔍 Security Testing
```bash
# Run security validation
python tests/robust_security_validation.py

# Check for vulnerabilities
pip install safety
safety check

# Run dependency audit
pip install bandit
bandit -r backend/
```

## 📱 Frontend

### 🏗️ Frontend Architecture
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   🎨 UI       │    │   🔄 State     │    │   🌐 Network   │
│   Screens       │◄──►│   Management    │◄──►│   Services      │
│   (Flutter)    │    │   (BLoC)       │    │   (Dio)        │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   🔐 Crypto     │    │   💾 Storage    │    │   🔧 Utils      │
│   (Signal)      │    │   (Secure)      │    │   (Helpers)     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### 📁 Frontend Structure
```
lib/
├── core/                  # Core utilities and constants
│   ├── constants/         # API constants and app settings
│   ├── theme/            # App theme and styling
│   └── utils/            # Helper functions
├── data/                 # Data layer
│   ├── models/           # Data models (User, Message, etc.)
│   ├── services/         # API services and repositories
│   └── mock/            # Mock data for testing
├── presentation/         # UI layer
│   ├── screens/          # App screens
│   └── widgets/          # Reusable UI components
├── crypto/               # Encryption implementation
└── main.dart             # App entry point
```

### 🎨 UI Components
- **Authentication**: Login, registration, password reset
- **Messaging**: Chat interface, message bubbles
- **File Sharing**: Upload progress, file preview
- **Settings**: Profile, preferences, security
- **Navigation**: Bottom navigation, app routing

## 🔧 Backend

### 🏗️ Backend Architecture
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   🔌 Auth       │    │   💬 Messages  │    │   📁 Files     │
│   Service       │    │   Service       │    │   Service       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   🗄️ Database   │    │   📦 Cache      │    │   🔐 Crypto     │
│   (MongoDB)     │    │   (Redis)       │    │   (Signal)      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### 📁 Backend Structure
```
backend/
├── routes/               # API route handlers
│   ├── auth.py         # Authentication endpoints
│   ├── messages.py     # Messaging endpoints
│   ├── files.py        # File upload/download
│   └── users.py        # User management
├── models/               # Data models and schemas
├── services/             # Business logic services
├── crypto/               # Encryption implementation
├── utils/                # Helper utilities
├── config.py             # Application configuration
└── main.py              # FastAPI application entry
```

### 🔌 Authentication Flow
```python
# User Registration
POST /auth/register
→ Validate input
→ Hash password
→ Create user in MongoDB
→ Generate JWT tokens
→ Return user data with tokens

# User Login  
POST /auth/login
→ Validate credentials
→ Generate JWT access + refresh tokens
→ Return authenticated session

# Token Refresh
POST /auth/refresh
→ Validate refresh token
→ Generate new access token
→ Return updated tokens
```

## 📈 Monitoring

### 📊 Health Checks
```bash
# Application health
curl https://zaply.in.net/health

# Database health
curl https://zaply.in.net/api/v1/health/db

# Redis health
curl https://zaply.in.net/api/v1/health/redis
```

### 📈 Metrics Collection
```yaml
# Prometheus metrics
- http_requests_total
- message_delivery_duration
- file_upload_size_bytes
- active_websocket_connections
- authentication_events
```

### 🔍 Log Analysis
```bash
# Application logs
docker-compose logs backend

# Nginx access logs
docker-compose exec nginx tail -f /var/log/nginx/access.log

# Error logs
docker-compose logs backend | grep ERROR
```

### 🚨 Alerting Setup
```yaml
# Grafana alerts
- High error rate (> 5/min)
- Database connection failures
- High memory usage (> 80%)
- SSL certificate expiry
- Disk space low (< 10%)
```

## 🤝 Contributing

### 🍴 Development Workflow
1. **Fork** the repository
2. **Create** feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** changes (`git commit -m 'Add amazing feature'`)
4. **Push** to branch (`git push origin feature/amazing-feature`)
5. **Create** Pull Request

### 📝 Code Style
- **Python**: Follow PEP 8, use Black formatter
- **Dart**: Follow official Dart style guide
- **Commits**: Conventional Commits specification
- **Documentation**: Update README for new features

### 🧪 Testing Requirements
- **Backend**: All tests must pass (`pytest`)
- **Frontend**: All tests must pass (`flutter test`)
- **Integration**: End-to-end tests for new features
- **Security**: Security tests for authentication changes

### 🐛 Bug Reports
```markdown
## Bug Description
- **Version**: v1.0.0
- **Environment**: Production/Docker
- **Expected**: What should happen
- **Actual**: What actually happens
- **Steps**: Steps to reproduce
- **Logs**: Relevant error logs
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### 📜 MIT License Summary
- ✅ **Commercial use**: Allowed
- ✅ **Modification**: Allowed
- ✅ **Distribution**: Allowed
- ✅ **Private use**: Allowed
- ❌ **Liability**: No warranty
- ❌ **Trademark**: No trademark grant

## 🙏 Acknowledgments

- **Signal Protocol**: For E2EE implementation
- **FastAPI**: For excellent web framework
- **Flutter**: For cross-platform development
- **MongoDB**: For scalable database solution
- **Redis**: For high-performance caching
- **Docker**: For containerization platform

## 📞 Support

### 🆘 Getting Help
- **Documentation**: [Wiki](https://github.com/your-org/hypersend/wiki)
- **Issues**: [GitHub Issues](https://github.com/your-org/hypersend/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/hypersend/discussions)
- **Email**: support@zaply.in.net

### 📚 Additional Resources
- **API Documentation**: https://zaply.in.net/docs
- **Development Guide**: https://zaply.in.net/dev-guide
- **Security Policy**: https://zaply.in.net/security
- **Privacy Policy**: https://zaply.in.net/privacy

---

<div align="center">
  <strong>🚀 Hypersend - Secure Messaging for the Modern World</strong><br>
  <em>Fast. Secure. Chat.</em>
</div>
