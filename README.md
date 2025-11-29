# 🚀 HyperSend

**HyperSend** is a modern, **chat + large-file transfer** application built with a pure Python stack. Self-host fast messaging and share very large files (tested up to ~40 GB) from your own server or VPS, with a mobile-first UI that can be built into an **optimized Android APK**.

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Latest-009688.svg)](https://fastapi.tiangolo.com/)
[![Flet](https://img.shields.io/badge/Flet-Latest-purple.svg)](https://flet.dev/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## ✨ Key Features

### 🔐 **Secure Authentication**
- Email + password authentication with JWT tokens
- Secure session management with refresh tokens
- Password reset functionality
- Token-based authorization

### 💬 **Real-Time Messaging**
- 1-to-1 and group chats
- Chat list with last message preview and timestamps
- Send/delete messages
- Mark messages as read
- Saved messages feature (like Telegram)
- Message search and filtering

### 📁 **Large File Transfer**
- Chunked upload/download with resume support
- Files up to **40 GB** (configurable)
- Progress tracking and checksums
- Automatic cleanup of expired uploads
- Storage quota management per user

### 🔄 **P2P File Transfer**
- Optional peer-to-peer mode
- Server handles signaling only
- WebSocket-based real-time sync
- No permanent server storage

### 🎨 **Modern Mobile-First UI**
- Built with Flet (Python → Flutter)
- Material Design 3 theming
- Smooth animations and transitions
- Responsive layouts
- Dark/Light mode support
- File picker and downloads management

### 📱 **Android APK Support**
- **NEW**: Optimized build process
- **NEW**: HTTP/2 enabled for 2x faster requests
- **NEW**: Connection pooling and keepalive
- **NEW**: Automated build script
- Release build with optimizations
- APK size: ~25-35 MB

### 🐳 **Production-Ready Deployment**
- Fully Dockerized stack
- Docker Compose for easy orchestration
- Nginx configuration for HTTPS and WebSockets
- Health checks and auto-restart
- Scalable architecture

### 💾 **Self-Hosted Storage**
- Local filesystem storage
- No cloud dependencies
- Configurable storage paths
- Optional external volume mounting

---

## 🛠 Tech Stack

| Layer | Technology | Role |
|-------|-----------|------|
| **Frontend** | Flet (Python/Flutter) | Cross-platform UI with native performance |
| **Backend** | FastAPI (Python) | High-performance REST APIs |
| **Database** | MongoDB | NoSQL document store |
| **Auth** | JWT + bcrypt | Secure token-based authentication |
| **Storage** | Local filesystem | Self-hosted file storage |
| **Deployment** | Docker + Compose | Containerized production deployment |
| **Networking** | HTTP/2 + WebSockets | Fast real-time communication |

---

## 📦 Project Structure

```text
hypersend/
├── backend/                     # FastAPI backend
│   ├── routes/                  # API endpoints
│   │   ├── auth.py             # Authentication
│   │   ├── users.py            # User management
│   │   ├── chats.py            # Chat operations
│   │   ├── files.py            # File uploads/downloads
│   │   └── p2p_transfer.py     # P2P WebSocket handler
│   ├── models.py               # Pydantic models
│   ├── database.py             # MongoDB connection
│   ├── config.py               # Configuration
│   ├── main.py                 # Application entry point
│   ├── Dockerfile
│   └── requirements.txt
│
├── frontend/                    # Flet frontend
│   ├── app.py                  # Main application
│   ├── api_client.py           # HTTP client wrapper
│   ├── update_manager.py       # Auto-update checker
│   ├── build_apk.py            # ⭐ NEW: Automated APK builder
│   ├── .env.production         # ⭐ NEW: Production config
│   ├── assets/                 # Images, icons
│   ├── Dockerfile
│   └── requirements.txt
│
├── data/                        # File storage (gitignored)
│   ├── files/                  # Uploaded files
│   └── tmp/                    # Temporary chunks
│
├── docker-compose.yml           # Docker orchestration
├── nginx.conf                   # Reverse proxy config
├── pyproject.toml              # Python package config
├── .env.example                # Environment template
└── README.md
```

---

## 📋 Prerequisites

- **Python 3.11+**
- **MongoDB** (local or remote)
- **Docker & Docker Compose** (for containerized deployment)
- **40+ GB disk space** (for large file transfers)
- **Android SDK** (optional, for APK builds)

---

## 🚀 Quick Start

### Option 1: Local Development

#### 1. Clone Repository

```bash
git clone https://github.com/Mayankvlog/Hypersend.git
cd Hypersend
```

#### 2. Setup Environment

```bash
# Copy environment template
cp .env.example .env

# Edit .env with your configuration
# Set MONGODB_URI, SECRET_KEY, API_BASE_URL, etc.
```

#### 3. Start Backend

```bash
# Install dependencies
pip install -r backend/requirements.txt

# Run backend
python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

Backend available at:
- API: `http://localhost:8000`
- Docs: `http://localhost:8000/docs`
- Health: `http://localhost:8000/health`

#### 4. Start Frontend

```bash
# Install dependencies
pip install -r frontend/requirements.txt

# Run frontend
python frontend/app.py
```

The Flet app will open as a desktop window with mobile-like layout.

---

### Option 2: Docker (Recommended for Production)

#### 1. Configure Environment

```bash
cp .env.example .env
# Edit .env with production values
```

#### 2. Start Services

```bash
# Build and start all services
docker-compose up --build -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

Services:
- **MongoDB**: `localhost:27017`
- **Backend**: `http://localhost:8000`
- **Frontend**: `http://localhost:8550`

---

## 📱 Building Android APK (Optimized)

### 🚀 Quick Build (Recommended)

```bash
cd frontend
python build_apk.py
```

This automated script will:
- ✅ Load production configuration
- ✅ Update dependencies with HTTP/2 support
- ✅ Clean old builds
- ✅ Build optimized release APK
- ✅ Report APK location and size

**Expected time:**
- First build: 10-15 minutes (downloads Flutter SDK ~500MB)
- Subsequent builds: 3-5 minutes

**APK location:** `frontend/build/apk/app-release.apk`

### 🛠 Manual Build

```bash
cd frontend

# Install dependencies with HTTP/2 support
pip install -r requirements.txt --upgrade

# Copy production configuration
copy .env.production .env  # Windows
# OR
cp .env.production .env    # Linux/Mac

# Build optimized APK
flet build apk --name HyperSend --org com.hypersend --release --optimize
```

### ⚡ Performance Optimizations

**Network Layer:**
- ✅ HTTP/2 protocol enabled (2x faster requests)
- ✅ Connection pooling (20 max, 10 keepalive)
- ✅ Optimized timeouts (15s connect, 45s read, 30s write)
- ✅ Connection keepalive (30s expiry)

**Application Layer:**
- ✅ Debug mode disabled in production
- ✅ Release build with code optimization
- ✅ Lazy loading for chat messages
- ✅ Memory-efficient UI rendering
- ✅ Reduced memory footprint

**Build Optimizations:**
- ✅ Release mode compilation
- ✅ Dead code elimination
- ✅ Resource minification
- ✅ Optimized asset bundling

### 📚 Build Documentation

- **English Guide**: [`frontend/BUILD_APK.md`](frontend/BUILD_APK.md)
- **Hindi Guide**: [`frontend/APK_BUILD_HINDI.md`](frontend/APK_BUILD_HINDI.md)

---

## 🔑 API Endpoints

### Authentication (`/api/v1/auth`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/register` | Register new user |
| POST | `/login` | Login and get tokens |
| POST | `/logout` | Logout and invalidate token |
| POST | `/refresh` | Refresh access token |
| POST | `/forgot-password` | Request password reset |
| POST | `/reset-password` | Reset password with token |

### Users (`/api/v1/users`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/me` | Get current user profile |
| GET | `/search` | Search users by email/name |
| PATCH | `/me` | Update profile |

### Chats (`/api/v1/chats`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | List user's chats |
| POST | `/` | Create new chat |
| GET | `/{chat_id}` | Get chat details |
| GET | `/{chat_id}/messages` | Get chat messages |
| POST | `/{chat_id}/messages` | Send message |
| GET | `/saved` | Get/create saved messages chat |

### Messages (`/api/v1/messages`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/{message_id}/save` | Save message |
| POST | `/{message_id}/unsave` | Unsave message |
| GET | `/saved` | Get all saved messages |
| DELETE | `/{message_id}` | Delete message |
| PATCH | `/{message_id}/read` | Mark as read |

### Files (`/api/v1/files`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/init` | Initialize chunked upload |
| PUT | `/{upload_id}/chunk` | Upload single chunk |
| POST | `/{upload_id}/complete` | Complete upload |
| POST | `/{upload_id}/cancel` | Cancel upload |
| GET | `/{file_id}/download` | Download file |
| GET | `/{file_id}/info` | Get file metadata |
| DELETE | `/{file_id}` | Delete file |

---

## 🌐 Production Deployment

### VPS Deployment

#### 1. Setup VPS

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Docker Compose
sudo apt install docker-compose -y
```

#### 2. Clone and Configure

```bash
git clone https://github.com/Mayankvlog/Hypersend.git
cd Hypersend

# Configure environment
cp .env.example .env
nano .env  # Edit with your values
```

**Important environment variables:**
```bash
# MongoDB (use remote server for production)
MONGODB_URI=mongodb://your-mongo-server:27017/hypersend

# Security (generate strong random key)
SECRET_KEY=your-super-secret-key-here

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
API_BASE_URL=http://your-vps-ip:8000

# Storage
DATA_ROOT=/data
MAX_FILE_SIZE_BYTES=42949672960  # 40 GB

# Production mode
DEBUG=False
```

#### 3. Start Services

```bash
# Start in detached mode
docker-compose up -d

# Check logs
docker-compose logs -f backend

# Check status
docker-compose ps
```

#### 4. Configure Firewall

```bash
# Allow HTTP, HTTPS, and API port
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 8000/tcp
sudo ufw enable
```

### Nginx Reverse Proxy (Optional)

For production with HTTPS:

```nginx
# /etc/nginx/sites-available/hypersend
server {
    listen 80;
    server_name api.yourdomain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name api.yourdomain.com;

    # SSL certificates (use Let's Encrypt)
    ssl_certificate /etc/letsencrypt/live/api.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.yourdomain.com/privkey.pem;

    # Large file uploads
    client_max_body_size 0;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
    proxy_request_buffering off;

    # Backend proxy
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_http_version 1.1;
        
        # WebSocket support
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

Enable and restart:
```bash
sudo ln -s /etc/nginx/sites-available/hypersend /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

---

## 🧪 Testing

### Backend Tests

```bash
# Run tests
pytest backend/tests/

# With coverage
pytest --cov=backend backend/tests/
```

### Frontend Testing

```bash
# Test on desktop
python frontend/app.py

# Test API connectivity
python -c "import httpx; print(httpx.get('http://localhost:8000/health').json())"
```

### APK Testing

```bash
# Install on connected Android device
adb install frontend/build/apk/app-release.apk

# View logs
adb logcat | grep flutter
```

---

## 🐛 Troubleshooting

### Backend Issues

**MongoDB connection failed:**
```bash
# Check MongoDB is running
sudo systemctl status mongod

# Test connection
mongosh mongodb://localhost:27017/hypersend
```

**Port already in use:**
```bash
# Find process using port 8000
lsof -i :8000  # Linux/Mac
netstat -ano | findstr :8000  # Windows

# Kill process or change API_PORT in .env
```

### Frontend Issues

**Cannot connect to backend:**
1. Check backend is running: `curl http://localhost:8000/health`
2. Verify `API_BASE_URL` in `.env` or `frontend/.env.production`
3. Check firewall allows port 8000

**APK build is slow:**
- First build downloads Flutter SDK (~500MB) - normal!
- Subsequent builds are much faster (3-5 minutes)
- Exclude `frontend/build` from Windows Defender
- Use SSD for faster builds

**Login fails with 404:**
- Ensure `API_BASE_URL` does NOT include `/api/v1` suffix
- Correct: `http://your-vps:8000`
- Wrong: `http://your-vps:8000/api/v1`

### File Upload Issues

**Upload fails or times out:**
```bash
# Check disk space
df -h  # Linux
Get-PSDrive  # Windows PowerShell

# Check permissions on data directory
ls -la data/  # Linux
icacls data\  # Windows

# Increase timeout in .env
UPLOAD_EXPIRE_HOURS=48
```

---

## 🔧 Configuration Reference

### Environment Variables

```bash
# MongoDB
MONGODB_URI=mongodb://localhost:27017/hypersend

# Security
SECRET_KEY=your-secret-key-min-32-chars
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=30

# API Server
API_HOST=0.0.0.0
API_PORT=8000
API_BASE_URL=http://localhost:8000

# File Storage
DATA_ROOT=./data
CHUNK_SIZE=4194304                    # 4 MB chunks
MAX_FILE_SIZE_BYTES=42949672960       # 40 GB max
MAX_PARALLEL_CHUNKS=4
UPLOAD_EXPIRE_HOURS=24

# Rate Limiting
RATE_LIMIT_PER_USER=100
RATE_LIMIT_WINDOW_SECONDS=60

# Development
DEBUG=False  # Set to True only for development
```

---

## 📊 Performance Benchmarks

### API Response Times
- Health check: < 10ms
- Login/Register: 100-200ms
- Chat list: 50-150ms
- File upload (4MB chunk): 1-3s (depends on network)

### File Transfer Performance
- Local network: ~100 MB/s
- Internet (100 Mbps): ~10 MB/s
- Maximum tested: 40 GB file successfully transferred

### Mobile App Performance
- APK size: 25-35 MB
- App startup: < 2s
- Chat list render: < 100ms
- HTTP/2 requests: 2x faster than HTTP/1.1

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [FastAPI](https://fastapi.tiangolo.com/) - Modern Python web framework
- [Flet](https://flet.dev/) - Python framework for building Flutter apps
- [MongoDB](https://www.mongodb.com/) - NoSQL database
- [Docker](https://www.docker.com/) - Containerization platform

---

## 📞 Support & Contact

- **GitHub Issues**: [Report bugs or request features](https://github.com/Mayankvlog/Hypersend/issues)
- **Documentation**: Check `frontend/BUILD_APK.md` for APK build details
- **Email**: [Your contact email]

---

## 🗺️ Roadmap

### ✅ Completed
- [x] JWT authentication
- [x] Real-time messaging
- [x] Large file transfer (40GB)
- [x] Android APK support
- [x] HTTP/2 optimization
- [x] Docker deployment
- [x] Password reset
- [x] Saved messages

### 🚧 In Progress
- [ ] End-to-end encryption
- [ ] Voice messages
- [ ] Video calls
- [ ] iOS app support

### 📅 Planned
- [ ] Desktop apps (Windows/Mac/Linux)
- [ ] Message reactions
- [ ] Stickers and GIFs
- [ ] Cloud storage integration
- [ ] Multi-device sync
- [ ] Bot API

---

## 📈 Statistics

![Python](https://img.shields.io/badge/Python-99.4%25-blue)
![Dockerfile](https://img.shields.io/badge/Dockerfile-0.6%25-blue)

---

## ⭐ Star History

If you find this project useful, please give it a star! ⭐

---

**Built with ❤️ by [Mayankvlog](https://github.com/Mayankvlog)**

**Self-host your own Telegram/WhatsApp alternative today! 🚀**



