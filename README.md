# 🚀 HyperSend

**HyperSend** is a modern, Telegram/WhatsApp‑style **chat + large‑file transfer** application built with a pure Python stack.
It lets you self‑host fast messaging and share very large files (tested up to ~40 GB) from your own server or VPS, with a
mobile‑first UI that can be built into an Android APK.

---

## ✨ Key Features

- 🔐 **Secure Authentication**  
  Email + password auth, bcrypt‑hashed passwords, JWT‑based sessions (stateless, secure).

- 💬 **Chats & Messages**  
  1‑to‑1 and group chats, chat list with last‑message preview and timestamps, send/delete messages,
  mark messages as read.

- 📁 **Large File Transfer (Server‑Stored)**  
  Chunked upload/download APIs, storing file chunks and merged files on local storage under `/data`,
  designed for files up to ~40 GB (configurable).

- 🔄 **P2P File Transfer (WhatsApp‑style mode)**  
  Optional mode where files are not stored permanently on the server. The backend only handles
  signalling/relay over WebSockets while metadata (filename, size, status) is stored in MongoDB.

- 🎨 **Modern, Mobile‑First UI (Flet Frontend)**  
  Flet (Python → Flutter) based interface with:
  - Login / Register screens
  - Chat list (avatars, last message, timestamps)
  - Chat detail (text + file messages, download buttons)
  - File picker upload & downloads to the user’s Downloads folder

- 🐳 **Fully Dockerized & Deployable**  
  Separate Dockerfiles for backend and frontend, plus `docker-compose.yml` for running the full
  stack (backend, frontend, data volumes) in one command. Includes sample `nginx.conf` for HTTPS,
  WebSockets, and large uploads.

- 💾 **Self‑Hosted Storage, No Cloud Lock‑in**  
  Files are stored on a local filesystem (`/data`) by default. You can swap this for any mounted
  volume or attach external storage as needed.

---

## 🛠 Tech Stack

| Layer      | Technology           | Role                                            |
|-----------|----------------------|-------------------------------------------------|
| Frontend  | **Flet (Python)**    | Cross‑platform, mobile‑first interactive UI     |
| Backend   | **FastAPI (Python)** | REST/JSON APIs, auth, chats, files, P2P         |
| Database  | **MongoDB**          | NoSQL store for users, chats, messages, files   |
| Auth      | **JWT + Passlib**    | Token‑based auth, bcrypt password hashing       |
| Storage   | Local `/data` dir    | File chunks + merged files (self‑hosted)        |
| Infra     | Docker + Compose     | Local dev + VPS deployment                      |

---

## 📦 Project Structure

```text
hypersend/
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
│   │   └── main.py               # FastAPI app entrypoint
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── app.py                    # Flet application
│   ├── assets/                   # Images, icons
│   ├── Dockerfile
│   └── requirements.txt
├── data/                         # File uploads (gitignored)
├── docker-compose.yml
├── nginx.conf                    # Example Nginx reverse proxy config
├── .env.example
└── README.md
```

---

## 📦 Installing Dependencies with pyproject.toml

From the project root (where `pyproject.toml` is):

```bash
# Sirf backend deps
pip install ".[backend]"

# Sirf frontend deps
pip install ".[frontend]"

# Ya full project deps
pip install .
```


### 1. Clone & Setup

```bash
git clone https://github.com/Mayankvlog/Hypersend.git
cd Hypersend
cp .env.example .env
```

Edit `.env` as needed:

```env
MONGODB_URI=mongodb://localhost:27017/hypersend
SECRET_KEY=your-very-secure-random-secret-key-here
DATA_ROOT=./data
```

### 2. Backend (FastAPI)

From the project root:

```bash
pip install -r backend/requirements.txt
python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

Backend will be available at:
- API base: `http://localhost:8000`
- API docs (Swagger): `http://localhost:8000/docs`

### 3. Frontend (Flet)

From the project root:

```bash
pip install -r frontend/requirements.txt
python frontend/app.py
```

The Flet app will open as a desktop window (mobile‑like layout). It will talk to the backend using
`API_URL` / `API_BASE_URL` defined in config.

---

## 🐳 Running with Docker (Recommended)

### 1. Configure Environment

Copy and edit env file:

```bash
cp .env.example .env
```

Set at least:

```env
MONGODB_URI=mongodb://mongodb:27017/hypersend
SECRET_KEY=your-very-secure-random-secret-key-here
DATA_ROOT=/data
```

### 2. Start Stack

```bash
docker-compose up --build
# or in detached mode
docker-compose up -d
```

Default services (may vary based on your compose):
- Backend API: `http://localhost:8000`
- Frontend UI: `http://localhost:8550`

`./data` on the host is mounted to `/data` in the container for file storage.

---

## 📱 Building Android APK

HyperSend’s frontend can be packaged as an Android app using Flet.

### 1. Set Production API URL

In `frontend/app.py` (or config module), set your production API endpoint:

```python
API_URL = "https://your-api-domain.com"  # Change before building
```

### 2. Build APK

From the `frontend/` directory, inside the virtualenv:

```bash
cd frontend
pip install -r requirements.txt
flet build apk --module-name app
```

The generated APK will appear under something like:

```text
frontend/build/apk/HyperSend.apk
```

You can then distribute the APK via:
- Direct download
- Pixeladz / Uptodown
- Google Play Store (requires a developer account)

---

## 🔑 Important API Endpoints (Backend)

### Authentication
- `POST /auth/register` – Register new user
- `POST /auth/login` – Login
- `POST /auth/logout` – Logout

### Chats
- `GET /chats/` – List user’s chats
- `POST /chats/` – Create new chat
- `GET /chats/{chat_id}` – Chat details
- `GET /chats/{chat_id}/messages` – Messages in a chat

### Messages
- `POST /messages/` – Send message
- `PATCH /messages/{message_id}/read` – Mark as read
- `DELETE /messages/{message_id}` – Delete message

### Files (Server‑Stored)
- `POST /files/upload/start` – Start chunked upload
- `POST /files/upload/chunk/{file_id}` – Upload chunk
- `GET /files/download/{file_id}` – Download file
- `GET /files/{file_id}/info` – File metadata
- `DELETE /files/{file_id}` – Delete file

File chunk size (in `backend/app/routes/files.py`):

```python
CHUNK_SIZE = 5 * 1024 * 1024  # 5 MB chunks (adjustable)
```

---

## 🌐 Production Deployment (VPS Example)

On your server:

```bash
git clone <your-repo>
cd hypersend
cp .env.example .env
# Edit .env with production MONGODB_URI, SECRET_KEY, DATA_ROOT, API_BASE_URL
docker-compose up -d
```

Example Nginx reverse proxy (HTTPS, WebSockets, large uploads):

```nginx
# HTTP → HTTPS
server {
  listen 80;
  server_name api.yourdomain.com;
  return 301 https://$host$request_uri;
}

# API behind Uvicorn (WS + large uploads)
server {
  listen 443 ssl http2;
  server_name api.yourdomain.com;

  ssl_certificate     /etc/letsencrypt/live/api.yourdomain.com/fullchain.pem;
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

---

## 🔒 Security & Ops Notes

- Always set a strong, unique `SECRET_KEY` in production.
- Use strong MongoDB credentials; bind MongoDB to private/local interfaces only.
- Put the backend behind HTTPS (Nginx/Caddy/other reverse proxy).
- Consider rate‑limiting uploads and adding virus‑scanning for uploaded files.
- Set up regular backups for MongoDB and file storage.

### Storage Layout

```text
/data/uploads/
  ├── {file_id}/
  │   ├── chunk_0
  │   ├── chunk_1
  │   └── filename.ext  # Final merged file
```

Example cron to clean files older than 30 days:

```bash
find /data/uploads -mtime +30 -type f -delete
```

---

## 🧪 Troubleshooting (Common Issues)

**MongoDB connection problems**
- Check connection string and credentials.
- Ensure `mongod` is running and not firewalled.
- Test manually:

```bash
mongosh "mongodb://localhost:27017/hypersend"
```

**File upload fails**
- Check disk space (`df -h` on Linux).
- Check permissions on `/data` or the host‑mounted directory.
- Tune `CHUNK_SIZE` for your network constraints.

**Frontend cannot reach backend**
- Confirm backend is running on the expected host/port.
- Verify `API_URL` / `API_BASE_URL` on the frontend.
- Check CORS settings in `backend/app/main.py` if calling from browsers.

---

> **One‑line summary:** HyperSend is a Python‑based, self‑hosted **chat + large file transfer platform** combining
> a FastAPI + MongoDB backend with a Flet UI, deployable with Docker and shippable as an Android APK.
