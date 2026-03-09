# zaply - Secure Messaging Platform

A modern, full-featured encrypted messaging application with real-time communication, end-to-end encryption, and multi-platform support across web, mobile, and desktop.

## Overview

zaply is an enterprise-grade messaging solution built with privacy-first principles. It provides seamless, secure communication with advanced features like file sharing, location tracking, user blocking, and comprehensive rate limiting. The platform is containerized with Docker/Kubernetes for scalable deployment.

## Key Features

- **End-to-End Encryption (E2EE)**: Military-grade AES encryption for all messages and files
- **Real-Time WebSocket Communication**: Instant message delivery with WebSocket protocol
- **Multi-Platform Support**: Web, iOS, Android, macOS, Windows, and Linux native apps
- **User Authentication**: JWT-based authentication with email verification and OTP support
- **User Blocking System**: Privacy controls to block unwanted contacts with persistent storage
- **Secure File Sharing**: Encrypted file upload/download with checksum verification
- **Location Sharing**: Real-time GPS location sharing with friends and group support
- **Emoji Support**: Full Unicode emoji handling with custom emoji library
- **Rate Limiting**: DDoS protection with configurable request throttling
- **Database Proxy**: Advanced connection pooling and query management
- **Notification Service**: Push notifications for mobile and web clients
- **Rich Authentication**: Multi-factor authentication support with recovery codes

## Technology Stack

**Backend Infrastructure:**
- FastAPI & Flask (Python) for API endpoints
- MongoDB for persistent storage with indexes
- Redis for caching and session management
- WebSockets for real-time messaging
- JWT tokens for stateless authentication
- OpenSSL/cryptography for encryption operations

**Frontend Applications:**
- Flutter framework for cross-platform mobile and web UI
- HTML5/CSS3/JavaScript for web application
- Provider state management for Flutter
- REST API consumption with proper error handling

**DevOps & Deployment:**
- Docker containerization for backend and frontend
- Docker Compose for local development orchestration
- Kubernetes manifests for production deployment
- Nginx reverse proxy configuration
- SSL/TLS certificates for secure communication

## Project Structure

```
hypersend/
├── backend/              # Python backend services
│   ├── auth/            # Authentication & authorization
│   ├── crypto/          # E2EE encryption logic
│   ├── routes/          # API endpoints
│   ├── services/        # Business logic
│   ├── utils/           # Helper utilities
│   ├── websocket/       # WebSocket handlers
│   ├── workers/         # Background jobs
│   ├── main.py          # FastAPI application
│   └── requirements.txt  # Python dependencies
├── frontend/            # Flutter cross-platform app
│   ├── lib/            # Flutter code
│   ├── android/        # Android native code
│   ├── ios/            # iOS native code
│   └── web/            # Web application files
├── certs/              # SSL/TLS certificates
├── data/               # Runtime data storage
├── scripts/            # Deployment & seed scripts
├── tests/              # Test suites
├── docker-compose.yml  # Development environment
├── kubernetes.yaml     # Production deployment
└── pyproject.toml      # Python project config
```

## Installation & Setup

### Prerequisites
- Python 3.9+ 
- Node.js 14+
- Flutter SDK
- Docker & Docker Compose
- MongoDB 5.0+
- Redis 6.0+

### Quick Start with Docker

```bash
docker-compose up -d
# Services accessible at localhost:8000 (API), :3000 (web)
```

### Manual Backend Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

### Frontend Setup

```bash
cd frontend
flutter pub get
flutter run -d chrome  # or -d ios/-d android for mobile
```

## Configuration

Key configuration files:
- `backend/config.py` - Database, Redis, JWT settings
- `backend/e2ee_crypto.py` - Encryption algorithm configuration
- `docker-compose.yml` - Service environment variables
- `kubernetes.yaml` - Production resource definitions

## Database

MongoDB initialization:
```bash
python backend/mongo_init.py
```

Seed test data:
```bash
python scripts/seed_mongodb.py
```

## Testing & Validation

```bash
# Run all tests
pytest tests/

# Run specific test suites
pytest test_all_fixes.py -v
pytest test_verification_complete.py -v
pytest COMPREHENSIVE_SECURITY_AUDIT.py -v

# Coverage report
pytest --cov=backend tests/
```

## API Documentation

Interactive Swagger documentation available at `/docs` when backend is running.

Core endpoints:
- `POST /auth/register` - User registration
- `POST /auth/login` - User authentication
- `POST /messages/send` - Send encrypted message
- `GET /messages/{chat_id}` - Fetch message history
- `POST /files/upload` - Upload and encrypt files
- `POST /users/{user_id}/block` - Block user
- `WebSocket /ws/{chat_id}` - Real-time messaging

## Security Features

- Messages encrypted with AES-256-GCM at rest and in transit
- JWT tokens with 24-hour expiration and refresh tokens
- CORS configuration for web security
- Input validation and sanitization on all endpoints
- Rate limiting: 100 requests/minute per user
- SQL injection prevention with parameterized queries
- XSS protection with Content Security Policy headers
- CSRF token validation for state-changing operations
- Secure file upload with MIME type validation

## Development

### Running in Debug Mode
```bash
export FLASK_ENV=development
export FLASK_DEBUG=1
python backend/main.py
```

### Build Docker Images
```bash
docker build -t hypersend-backend:latest ./backend
docker build -t hypersend-frontend:latest ./frontend
```

### Code Quality
```bash
flake8 backend/ --max-line-length=100
black backend/ --line-length=100
pylint backend/
```

## Deployment

### Production with Kubernetes
```bash
kubectl apply -f kubernetes.yaml
kubectl set image deployment/hypersend-backend \
  hypersend-backend=hypersend-backend:v1.0 --record
```

## Contributing

1. Create feature branch: `git checkout -b feature/amazing-feature`
2. Commit changes: `git commit -m 'Add amazing feature'`
3. Push branch: `git push origin feature/amazing-feature`
4. Open pull request with detailed description

## Troubleshooting

- **MongoDB connection failed**: Check connection string in config.py
- **WebSocket disconnects**: Verify nginx proxy_set_header configurations
- **File upload errors**: Ensure data/uploads/ directory has write permissions

## License

Proprietary - All rights reserved

## Contact & Support

Development Team: hypersend@example.com

---

**Last Updated**: March 2026 | **Version**: 1.0.0
