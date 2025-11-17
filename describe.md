# HyperSend – Project Description

**HyperSend** ek modern, Telegram/WhatsApp-jaisa **chat + large file transfer** application hai jo pure Python stack par bana hai. Iska goal hai users ko simple, secure aur fast tarike se messages aur bade files share karne ka option dena, saath hi Android APK ke through mobile app provide karna.

---

## 1. High-Level Overview

- Real-time messaging between users (1-to-1 / groups)
- Large file sharing with **chunked upload/download** (theoretically up to 40 GB)
- Mobile-friendly UI, jo Android app me convert ho sakta hai
- Self-hosted backend + database + storage (no AWS/GCP storage dependency by default)

---

## 2. Tech Stack

### Backend (folder: `backend/`)

- **Framework:** FastAPI (Python)
- **Database:** MongoDB (NoSQL)
- **Auth:** JWT (PyJWT) + Passlib (bcrypt password hashing)
- **File Handling:**
  - Chunked upload API:
    - `POST /api/v1/files/init` – upload session create karta hai
    - `PUT /api/v1/files/{upload_id}/chunk` – file chunks upload
    - `POST /api/v1/files/{upload_id}/complete` – chunks ko merge karke final file banata hai
  - File download API:
    - `GET /api/v1/files/{file_id}/download` – HTTP range support ke saath streaming
  - Files local filesystem me `/data` ke andar store hoti hain
- **P2P File Transfer:** (`backend/routes/p2p_transfer.py`)
  - WhatsApp-style P2P:
    - File server par store nahi hoti
    - Server sirf **relay/signaling** karta hai WebSockets ke through
    - Metadata (filename, size, status) MongoDB me save hota hai
- **Routers:**
  - `/api/v1/auth` – registration, login, logout
  - `/api/v1/users` – current user info, user management
  - `/api/v1/chats` – chats list, create chat, chat details, messages
  - `/api/v1/files` – server-side file upload/download
  - `/api/v1/p2p` – P2P transfer (sender/receiver WebSocket endpoints)
  - `/api/v1/updates` – app update-related APIs (optional)

### Frontend (folder: `frontend/`)

- **Framework:** Flet (Python-based UI, Flutter-style)
- **Features:**
  - Login / Register screen (email + password + username)
  - Chats list screen (last message preview, icons/avatars)
  - Chat detail screen:
    - Text messages
    - File messages (Download button)
  - File upload:
    - File picker se file choose
    - Chunked upload via backend APIs
  - File download:
    - Downloaded file ko user ke `Downloads` folder me save karta hai
- **Config:**
  - `API_URL` / `API_BASE_URL` env se read hota hai, jisse backend URL set kar sakte ho
- **Android APK:**
  - `flet build apk` se frontend ko Android app me build kar sakte ho

### Infrastructure & Tooling

- **Dockerized setup:**
  - `backend/Dockerfile` – FastAPI backend container
  - `frontend/Dockerfile` – Flet frontend container
  - `docker-compose.yml` – backend + frontend + data volume ko ek saath run karne ke liye
- **Reverse Proxy (Production):**
  - `nginx.conf` – HTTPS, WebSocket support, large uploads ke liye config example (Nginx reverse proxy)
- **Configs & Docs:**
  - `.env.example` – environment variables template (MONGODB_URI, SECRET_KEY, etc.)
  - `README.md` – project overview, local run, deployment guides
  - `more.md` – Google Cloud + Docker Hub + GitHub Actions deployment ka step-by-step plan

---

## 3. Features Summary

- 🔐 **Secure Authentication** – JWT-based login, hashed passwords
- 💬 **Real-time Chat** – FastAPI backend + HTTP APIs for chats/messages
- 📁 **Large File Transfer** – Chunked uploads, resumable pattern, streaming downloads
- 🔄 **P2P Transfer** – WhatsApp-style direct transfer via WebSockets (server stores only metadata)
- 📱 **Mobile-First UI** – Flet interface optimized for 400x850 window (Android-like)
- 🐳 **Docker Support** – Easily run with Docker/Docker Compose
- 💾 **Self-Hosted Storage** – Local `/data` directory for files by default (can be swapped to cloud storage)

---

## 4. Running Locally (Basic)

### Backend

```bash
# Project root se
pip install -r backend/requirements.txt
python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend

```bash
# Project root se
pip install -r frontend/requirements.txt
python frontend/app.py
```

---

## 5. Deployment Options (Short Overview)

- **Docker Compose (VPS / local server):**
  - `docker-compose up --build` se backend + frontend + data volume ek saath start
- **Cloud deployment:**
  - Google Cloud Run, Docker Hub, GitHub Actions ke saath CI/CD (details `more.md` me)
- **APK distribution:**
  - `flet build apk` → Android app build → Pixeladz, Uptodown, Play Store, etc.

---

Short me: **HyperSend** ek Python-based end-to-end system hai jo **FastAPI + MongoDB backend** aur **Flet frontend** ka use karke secure chat, large file sharing, aur P2P transfer provide karta hai, jise aap local, VPS ya cloud par deploy kar sakte ho, aur Android APK ke roop me distribute kar sakte ho.
