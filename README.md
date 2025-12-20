# 🚀 Hypersend - Setup & Deployment Guide

A modern, enterprise-grade, real-time messaging and P2P file transfer platform.

## 🎯 Quick Overview

**Hypersend** is a cross-platform messaging app with:
- ✅ Real-time chat (WebSocket support)
- ✅ Secure P2P file transfer 
- ✅ User authentication & permissions
- ✅ Full Docker containerization
- ✅ Production-ready Nginx reverse proxy

---

## 🛠️ Tech Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| **Backend** | FastAPI | 0.115.5+ |
| **Database** | MongoDB | 7.0 |
| **Frontend** | Flutter | 3.35.6+ |
| **Web Server** | Nginx | Alpine |
| **Containerization** | Docker & Docker Compose | Latest |
| **Auth** | JWT (HS256) | - |

---

## 📁 Project Structure

```
hypersend/
├── backend/                    # FastAPI backend
│   ├── main.py               # Application entry
│   ├── database.py           # MongoDB connection
│   ├── config.py             # Configuration & settings
│   ├── security.py           # JWT & authentication
│   ├── models.py             # Data models
│   ├── routes/               # API endpoints
│   │   ├── auth.py          # Authentication endpoints
│   │   ├── chats.py         # Chat management
│   │   ├── users.py         # User management
│   │   ├── files.py         # File operations
│   │   ├── p2p_transfer.py  # P2P file transfer (WebSocket)
│   │   └── updates.py       # Real-time updates
│   ├── auth/                 # Auth utilities
│   ├── Dockerfile            # Backend container
│   └── requirements.txt       # Python dependencies
│
├── frontend/                   # Flutter app
│   ├── lib/                  # Flutter source code
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
├── docker-compose.yml        # 🔧 **FIXED** - Now builds frontend locally
├── nginx.conf                # Nginx configuration
├── NGINX_QUICK_START.md      # Nginx setup guide
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
API_BASE_URL=http://139.59.82.105:8000
PRODUCTION_API_URL=http://139.59.82.105:8000
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
GET    /users/                 # List users
GET    /users/{user_id}        # User details
PUT    /users/{user_id}        # Update profile
DELETE /users/{user_id}        # Delete account
```

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
  -out /etc/nginx/ssl/cert.pem -subj '/CN=your-domain.com'
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

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Mayank Vlog** - [@Mayankvlog](https://github.com/Mayankvlog)

---

## 🆘 Support

For issues, questions, or feature requests, please open an issue on [GitHub Issues](https://github.com/Mayankvlog/Hypersend/issues).

---

**Last Updated**: December 14, 2025
**Status**: ✅ Production Ready


