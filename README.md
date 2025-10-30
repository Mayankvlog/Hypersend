# 🚀 HyperSend

**HyperSend** is a modern, Telegram-like chat and large-file transfer application built with Python, supporting file uploads up to **40 GB**. Built for Android APK deployment with a beautiful, interactive UI.

## ✨ Features

- 🔐 **Secure Authentication** - JWT-based auth with bcrypt password hashing
- 💬 **Real-time Messaging** - Fast, responsive chat interface
- 📁 **Large File Transfer** - Chunked upload/download supporting files up to 40 GB
- 🎨 **Modern UI** - Elegant dark/light themes with Material Design 3
- 📱 **Mobile-First** - Optimized for Android devices
- 🐳 **Fully Dockerized** - Easy deployment with Docker Compose
- 💾 **MongoDB Atlas** - Cloud database with free tier support
- 🔒 **Local Storage** - No AWS S3 or Google Cloud dependencies

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Frontend** | Flet (Python) | Cross-platform interactive UI |
| **Backend** | FastAPI (Python) | RESTful API with async support |
| **Database** | MongoDB Atlas | Cloud NoSQL database |
| **Auth** | PyJWT + Passlib | Secure token-based authentication |
| **Files** | Local `/data` directory | 40 GB chunked upload/download |
| **Container** | Docker + Docker Compose | Isolated deployment |

## 📋 Prerequisites

- Python 3.11+
- Docker & Docker Compose
- MongoDB Atlas account (free tier available)
- 40+ GB storage for file uploads

## 🚀 Quick Start

### 1. Clone & Setup

```bash
cd hyper_send
cp .env.example .env
```

### 2. Configure MongoDB Atlas

1. Create a free account at [MongoDB Atlas](https://www.mongodb.com/cloud/atlas)
2. Create a new cluster
3. Get your connection string
4. Update `.env` file:

```env
MONGODB_URL=mongodb+srv://username:password@cluster.mongodb.net/?retryWrites=true&w=majority
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
cd backend
pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```

**Frontend:**
```bash
cd frontend
pip install -r requirements.txt
python app.py
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

## 🎨 Customization

### Theme Colors (frontend/app.py)
```python
self.primary_color = "#0088cc"  # Telegram blue
self.bg_dark = "#0e1621"
self.bg_light = "#17212b"
```

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
# Edit .env with production values
docker-compose up -d
```

### Option 2: Android APK Distribution

1. Build APK: `flet build apk`
2. Upload to:
   - **Pixeladz** - https://pixeladz.com
   - **Uptodown** - https://www.uptodown.com
   - Google Play Store (requires developer account)

## 🔒 Security Considerations

- ✅ Change `SECRET_KEY` in production
- ✅ Use strong MongoDB Atlas passwords
- ✅ Enable MongoDB IP whitelist
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
- Verify IP whitelist in MongoDB Atlas
- Test connection: `ping` your cluster URL

**File Upload Fails:**
- Check disk space: `df -h`
- Verify `/data` permissions
- Increase chunk size for slow connections

**Frontend Can't Connect:**
- Ensure backend is running
- Check `API_URL` environment variable
- Verify CORS settings in `backend/app/main.py`

## 📝 License

MIT License - feel free to use for personal or commercial projects.

## 🤝 Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

## 📧 Support

For issues and questions:
- GitHub Issues: [Create an issue]
- Email: support@hypersend.app

---

**Built with ❤️ using Python, FastAPI, Flet, and MongoDB**
