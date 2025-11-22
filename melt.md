# HyperSend - Full Project Description

## 1. Idea

HyperSend is a self-hosted **chat + large file transfer** system. It gives a WhatsApp/Telegram style experience, but everything runs on your own server or VPS.

Key goals:
- 1-to-1 and group chat
- Large file sharing using chunked upload / download (designed for very big files, around 40 GB, configurable)
- Optional P2P-style file transfers where the server mainly relays and does not permanently store the file
- Pure Python stack, with a UI that can be turned into an Android APK
- Fully Dockerized, easy to deploy on a VPS (e.g. DigitalOcean)

---

## 2. Main Features

### 2.1 Authentication and Security
- Email + password login and registration
- Passwords stored with bcrypt hashing (via Passlib)
- JWT tokens for stateless authentication on each request

### 2.2 Chats and Groups
- Chat model supports both direct (1-to-1) and group conversations
- Typical chat features:
  - List of chats with last message preview and timestamps
  - Send, fetch and delete messages
  - Mark messages as read
- Groups are represented as chats with multiple members

### 2.3 Large File Transfer (Server-stored)
- Files are uploaded in chunks instead of a single huge request
- Basic flow:
  1. Client creates an upload session
  2. Client sends multiple chunk files to the backend
  3. Backend merges chunks to produce the final file
- Downloads are streamed over HTTP, with support for large files
- Files are stored under a configurable root directory, usually `/data`, which is mounted from the host using Docker volumes
- Each file typically has its own folder with `chunk_0`, `chunk_1`, etc., plus the final merged file

### 2.4 P2P-style File Transfer
- Optional P2P mode similar to WhatsApp:
  - Files are not permanently stored on the server
  - Server mainly provides signaling and relay via WebSockets
  - MongoDB stores file metadata (name, size, status) and session info
- This mode is useful when you want temporary transfers and do not want to fill server disk

### 2.5 Frontend (Flet UI)
- Implemented in the `frontend/` folder using Flet (Python UI on top of Flutter)
- Key screens:
  - Login / Register
  - Chat list (with avatars/icons and last message)
  - Chat detail (text messages and file messages, with download actions)
- File picker integration for uploads, wired into the chunked upload APIs of the backend
- Layout is mobile-first (around 400x850 window), so it looks and feels like an Android app
- Backend base URL is configurable through an environment variable such as `API_BASE_URL` (for example, `http://backend:8000` when using Docker)

### 2.6 Backend (FastAPI)
- Implemented in the `backend/` folder using FastAPI (Python)
- Typical routes (pattern):
  - `/api/v1/auth` - register, login, logout
  - `/api/v1/users` - current user info and user management
  - `/api/v1/chats` - create chats / groups, list chats, chat details, messages
  - `/api/v1/files` - server-side file upload and download (chunked)
  - `/api/v1/p2p` - P2P transfer signaling endpoints (WebSockets)
  - `/api/v1/updates` - optional app update metadata
- Structure (by folders):
  - `models/` - Pydantic models for users, chats, messages, files, sessions
  - `routes/` - routers for auth, chats, messages, files, p2p
  - `services/` - JWT handling, password hashing, MongoDB connection, and helpers

### 2.7 Database (MongoDB)
- Stores:
  - Users (email, hashed password, profile info)
  - Chats (direct or group, members, last message, timestamps)
  - Messages (chat id, sender, text content, file references, read status)
  - Upload sessions (progress state for chunked uploads)
  - P2P sessions (sender/receiver, metadata, status)
- Collections should have indexes on common query fields such as user id, chat id, and timestamps

### 2.8 Storage Layout
- Default storage root: `/data` (mapped from a host directory via Docker volume `./data:/data`)
- Each uploaded file usually lives under its own subdirectory containing:
  - Individual chunk files
  - The final merged file
- Old or unused files can be cleaned up with scripts or cron jobs

---

## 3. Docker and Deployment

### 3.1 Docker Structure
- `backend/Dockerfile` builds the FastAPI backend image
- `frontend/Dockerfile` builds the Flet frontend image
- Root `docker-compose.yml` defines:
  - `backend` service:
    - Image name like `${DOCKERHUB_USERNAME}/hypersend-backend:latest`
    - Exposes port 8000
    - Binds environment variables like `MONGODB_URI`, `SECRET_KEY`, `DATA_ROOT`
    - Mounts `./data` on `/data`
  - `frontend` service:
    - Image name like `${DOCKERHUB_USERNAME}/hypersend-frontend:latest`
    - Exposes port 8550
    - Reads `API_BASE_URL` so it can talk to the backend
  - Shared network `hypersend_network`

### 3.2 Running Locally with Docker
From the project root:

```bash
cp .env.example .env
# edit .env for MONGODB_URI, SECRET_KEY, DATA_ROOT

docker-compose up --build
# or
docker-compose up -d
```

Services:
- Backend API: http://localhost:8000
- API docs: http://localhost:8000/docs
- Frontend UI: http://localhost:8550

### 3.3 Local Development Without Docker

Backend:

```bash
pip install -r backend/requirements.txt
python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

Frontend:

```bash
pip install -r frontend/requirements.txt
python frontend/app.py
```

Make sure the frontend API base URL points to the backend (for example, `http://localhost:8000`).

### 3.4 Typical VPS / Cloud Deployment Flow
- Use a VPS (for example, a DigitalOcean Droplet)
- Install Docker and docker compose
- Clone the repo into a directory like `/srv/hypersend`
- Copy `.env.example` to `.env` and set production values (MongoDB URI, secret key, etc.)
- Run `docker compose up -d` to start backend and frontend
- Optionally put an Nginx reverse proxy in front for HTTPS, WebSockets, and large upload configuration


---

## 4. Android APK Build

From the `frontend/` directory:

```bash
cd frontend
# Set API URL inside the app (e.g. API_URL = "https://api.yourdomain.com")

flet build apk
```

The resulting APK can be sideloaded on Android devices or uploaded to distribution platforms.

---

## 5. CI/CD Overview (GitHub Actions + Docker + VPS)

A common CI/CD pattern for HyperSend looks like this:

1. On push to the main branch, GitHub Actions:
   - Builds backend and frontend Docker images
   - Pushes them to a Docker registry (Docker Hub or GHCR)
   - SSHes into your VPS, runs `git pull`, `docker compose pull`, and `docker compose up -d`

2. The VPS runs the updated containers defined in `docker-compose.yml`.

This gives you an automated pipeline from commit to live deployment, using the Docker and compose setup already present in the project.

---

## 6. Typical Use Cases

- Private WhatsApp/Telegram-style server for teams, communities, or friends
- Sharing very large files (dozens of GB) without third-party cloud storage
- End-to-end learning project for:
  - FastAPI and MongoDB
  - Chunked uploads and streaming downloads
  - Docker, docker compose, and reverse proxies
  - Building Python-based mobile-style UIs (Flet)

---

## 7. One-line Summary

HyperSend is a Python-based, self-hosted **chat + large file transfer** platform with FastAPI, MongoDB, and a Flet UI, supporting group messaging, huge file uploads, optional P2P-style transfers, Docker-based deployment, and Android APK builds in a single codebase.
