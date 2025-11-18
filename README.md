# 🚀 HyperSend

**HyperSend** is a modern, Telegram-like chat and large-file transfer application built with Python, supporting file uploads up to **40 GB**. Built for Android APK deployment with a beautiful, interactive UI.

## ✨ Features

- 🔐 **Secure Authentication** - JWT-based auth with bcrypt password hashing
- 💬 **Real-time Messaging** - Fast, responsive chat interface
- 📁 **Large File Transfer** - Chunked upload/download supporting files up to 40 GB
- 🎨 **Modern UI** - Elegant dark/light themes with Material Design 3
- 📱 **Mobile-First** - Optimized for Android devices
- 🐳 **Fully Dockerized** - Easy deployment with Docker Compose
- 💾 **MongoDB** - Self-hosted database (local or your server)
- 🔒 **Local Storage** - No AWS S3 or Google Cloud dependencies

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Frontend** | Flet (Python) | Cross-platform interactive UI |
| **Backend** | FastAPI (Python) | RESTful API with async support |
| **Database** | MongoDB | Self-hosted NoSQL database |
| **Auth** | PyJWT + Passlib | Secure token-based authentication |
| **Files** | Local `/data` directory | 40 GB chunked upload/download |
| **Container** | Docker + Docker Compose | Isolated deployment |

## 📋 Prerequisites

- Python 3.11+
- Docker & Docker Compose
- MongoDB Community Server (running locally or on your server)
- 40+ GB storage for file uploads

## 🚀 Quick Start

### 1. Clone & Setup

```bash
git clone https://github.com/Mayankvlog/Hypersend.git
cd Hypersend
cp .env.example .env
```

### 2. Configure MongoDB

1. Install MongoDB Community Server.
2. Ensure mongod is running and accessible.
3. Update `.env` file:

```env
MONGODB_URI=mongodb://localhost:27017/hypersend
SECRET_KEY=your-very-secure-random-secret-key-here
```

### 3. Run with Docker

```bash
# Build and start all services
docker-compose up --build

# Run in detached mode
docker-compose up -d
```

**Services:**
- Backend API: http://localhost:8000
- Frontend Web: http://localhost:8550
- API Docs: http://localhost:8000/docs

### 4. Run Locally (Development)

**Backend:**
```bash
# from project root
pip install -r backend/requirements.txt
python -m uvicorn backend.main:app --reload
```

**Frontend:**
```bash
pip install -r frontent/requirements.txt
python -m frontend.app
```

## 📱 Building Android APK

### Using Flet CLI

```bash
cd frontend

# Build APK
flet build apk

# The APK will be in: build/apk/HyperSend.apk
```

### Manual Configuration

Edit `frontend/app.py` and set your production API URL:

```python
API_URL = "https://your-api-domain.com"  # Change before building
```

## 🏗️ Project Structure

```
hyper_send/
├── backend/
│   ├── app/
│   │   ├── models/
│   │   │   └── models.py         # Pydantic models
│   │   ├── routes/
│   │   │   ├── auth.py           # Authentication endpoints
│   │   │   ├── chats.py          # Chat management
│   │   │   ├── messages.py       # Message handling
│   │   │   └── files.py          # File upload/download
│   │   ├── services/
│   │   │   ├── auth.py           # JWT & password hashing
│   │   │   └── database.py       # MongoDB connection
│   │   └── main.py               # FastAPI app
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── app.py                    # Flet application
│   ├── assets/                   # Images, icons
│   ├── Dockerfile
│   └── requirements.txt
├── data/                         # File uploads (gitignored)
├── docker-compose.yml
├── .env.example
└── README.md
```

## 🔑 API Endpoints

### Authentication
- `POST /auth/register` - Register new user
- `POST /auth/login` - Login user
- `POST /auth/logout` - Logout user

### Chats
- `GET /chats/` - Get user's chats
- `POST /chats/` - Create new chat
- `GET /chats/{chat_id}` - Get chat details
- `GET /chats/{chat_id}/messages` - Get chat messages

### Messages
- `POST /messages/` - Send message
- `PATCH /messages/{message_id}/read` - Mark as read
- `DELETE /messages/{message_id}` - Delete message

### Files
- `POST /files/upload/start` - Start chunked upload
- `POST /files/upload/chunk/{file_id}` - Upload chunk
- `GET /files/download/{file_id}` - Download file
- `GET /files/{file_id}/info` - Get file info
- `DELETE /files/{file_id}` - Delete file

### File Chunk Size (backend/app/routes/files.py)
```python
CHUNK_SIZE = 5 * 1024 * 1024  # 5MB chunks (adjustable)
```

## 🚢 Deployment

### Option 1: VPS/Cloud Server

```bash
# On your server
git clone <your-repo>
cd hyper_send
cp .env.example .env
# Edit .env with production values (MONGODB_URI, SECRET_KEY, API_BASE_URL, DATA_ROOT)
docker-compose up -d
```

#### Nginx reverse proxy (HTTPS, WebSocket, large uploads)
Example TLS config (Let’s Encrypt paths). Adjust domains.

```nginx
# HTTP → HTTPS
server {
  listen 80; server_name api.yourdomain.com;
  return 301 https://$host$request_uri;
}
# API behind Uvicorn (WS + large uploads)
server {
  listen 443 ssl http2; server_name api.yourdomain.com;
  ssl_certificate /etc/letsencrypt/live/api.yourdomain.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/api.yourdomain.com/privkey.pem;

  client_max_body_size 0;
  proxy_read_timeout 3600s;
  proxy_send_timeout 3600s;
  proxy_request_buffering off;

  location / {
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host $host;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
  }
}
```

### Option 2: Android APK Distribution

1. Build APK: `flet build apk`
2. Upload to:
   - **Pixeladz** - https://pixeladz.com
   - **Uptodown** - https://www.uptodown.com
   - Google Play Store (requires developer account)

### ⚙️ CI/CD with GitHub Actions (example)
Build Docker image on push and deploy to a VPS over SSH.

```yaml
name: deploy-backend
on:
  push:
    branches: [ main ]
    paths: [ 'backend/**', 'docker-compose.yml', '.env.example' ]
jobs:
  build-and-deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build image
        run: docker build -t ghcr.io/${{ github.repository }}-backend:latest ./backend
      - name: Login GHCR
        run: echo ${{ secrets.GHCR_TOKEN }} | docker login ghcr.io -u ${{ github.actor }} --password-stdin
      - name: Push image
        run: docker push ghcr.io/${{ github.repository }}-backend:latest
      - name: Deploy to VPS
        uses: appleboy/ssh-action@v1.0.3
        with:
          host: ${{ secrets.VPS_HOST }}
          username: ${{ secrets.VPS_USER }}
          key: ${{ secrets.VPS_SSH_KEY }}
          script: |
            cd /srv/hypersend
            docker compose pull && docker compose up -d --build
```

### 🔧 Environment notes
- Backend expects `MONGODB_URI` (not `MONGODB_URL`). If your compose uses `MONGODB_URL`, rename it or set both.
- For large files, ensure `DATA_ROOT=/data` and mount host `./data:/data` in compose.

### 🐞 APK build tips
- First build can take 10–20 minutes (Flutter/Gradle caches). Do not interrupt.
- Pre-cache: `flutter precache --android` then `flet build apk --flutter-build-args "--stacktrace"`.

## 🔒 Security Considerations

- ✅ Change `SECRET_KEY` in production
- ✅ Use strong MongoDB passwords
- ✅ Bind MongoDB to private/local interfaces and restrict via firewall
- ✅ Use HTTPS in production (reverse proxy with nginx/Caddy)
- ✅ Implement rate limiting for uploads
- ✅ Add virus scanning for uploaded files
- ✅ Set up backup for MongoDB

## 📊 Storage Management

Files are stored in `/data/uploads/` with structure:
```
/data/uploads/
  ├── {file_id}/
  │   ├── chunk_0
  │   ├── chunk_1
  │   └── filename.ext  # Final merged file
```

**Cleanup old files:**
```bash
# Add cron job to clean files older than 30 days
find /data/uploads -mtime +30 -type f -delete
```

## 🐛 Troubleshooting

**MongoDB Connection Issues:**
- Check connection string format
- Verify mongod bindIp and firewall rules
- Test connection: `mongosh "mongodb://localhost:27017/hypersend"`

**File Upload Fails:**
- Check disk space: `df -h`
- Verify `/data` permissions
- Increase chunk size for slow connections

**Frontend Can't Connect:**
- Ensure backend is running
- Check `API_URL` environment variable
- Verify CORS settings in `backend/app/main.py`


**Built with ❤️ using Python, FastAPI, Flet, and MongoDB**
