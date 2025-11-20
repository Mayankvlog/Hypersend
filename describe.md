# HyperSend – Project Description

## 1. What is HyperSend?

**HyperSend** ek modern, Telegram/WhatsApp‑style **chat + large file transfer** application hai, jo pure Python stack par bana hai.

Iska main goal:
- Users ko fast aur simple **messaging** dena
- Users ko **bahut bade files (theoretically ~40 GB)** share karne dena
- Ye sab aapke **khud ke server / VPS** par host ho sakta hai
- Frontend ko Android **APK** ke roop me build karke distribute kiya ja sakta hai

Short me: apna khud ka self‑hosted WhatsApp/Telegram + large file transfer system.

---

## 2. Major Features

1. **Secure Authentication**
   - Email + password based login / register
   - Passwords bcrypt hashing ke saath store hote hain
   - JWT tokens se authentication (stateless, secure)

2. **Chats & Messages**
   - User‑to‑user aur groups ke liye chat model
   - Chats list, last message preview, timestamps
   - Messages ko fetch, send, delete, read‑status mark karna

3. **Large File Transfer (Server‑stored)**
   - Chunked upload API (file ko multiple chunks me tod kar upload karta hai)
   - Chunked download / streaming for large files
   - Files local filesystem me `/data` directory ke andar store hoti hain
   - Theoretically ~40 GB tak ke files (configurable limit)

4. **P2P File Transfer (WhatsApp‑style)**
   - Ek mode jahan file server par permanently store nahi hoti
   - Server sirf WebSockets ke through **signalling + relay** karta hai
   - Metadata (filename, size, status) MongoDB me save hota hai

5. **Modern UI (Flet Frontend)**
   - Flet (Python → Flutter UI) ka use karke cross‑platform interface
   - Screens:
     - Login / Register
     - Chat list (avatars, last message)
     - Chat detail (text + file messages)
   - File picker se upload, buttons se download
   - Layout mobile‑first (approx 400×850 window) – easily Android look‑and‑feel

6. **Dockerized & Deployable**
   - Backend + frontend ke Dockerfiles
   - `docker-compose.yml` se pura stack (backend, frontend, data volumes) ek command me run
   - Nginx reverse proxy config example (`nginx.conf`) for HTTPS, WebSocket, large uploads

---

## 3. Tech Stack

| Layer        | Technology          | Role                                           |
|-------------|---------------------|------------------------------------------------|
| Frontend    | **Flet (Python)**   | Interactive UI, Android‑ready app             |
| Backend     | **FastAPI (Python)**| REST/JSON APIs, auth, chat, file endpoints    |
| Database    | **MongoDB**         | NoSQL store for users, chats, messages, files |
| Auth        | **JWT + Passlib**   | Token‑based auth, bcrypt password hashing     |
| Storage     | Local `/data` dir   | File chunks + merged files (self‑hosted)      |
| Container   | Docker + Compose    | Easy local + VPS deployment                   |

---

## 4. High‑Level Architecture

1. **Clients**
   - Flet desktop/mobile app (or APK)
   - HTTP/JSON requests + (optional) WebSockets

2. **Backend (FastAPI)**
   - Main app: `backend/main.py`
   - Routers (approx):
     - `/api/v1/auth` – register, login, logout
     - `/api/v1/users` – current user info, user management
     - `/api/v1/chats` – chats + messages
     - `/api/v1/files` – server‑stored file uploads/downloads
     - `/api/v1/p2p` – P2P transfer signalling
     - `/api/v1/updates` – app update metadata (optional)

3. **Database (MongoDB)**
   - Collections for users, chats, messages, upload sessions, p2p sessions, etc.
   - Designed for scalable read/write (indexes recommended on frequent fields).

4. **File Storage**
   - Path: `/data/...` (by default host volume se mount hota hai)
   - Each file ke liye ek folder + multiple `chunk_*` files + final merged file

5. **Infra / Deployment**
   - Local dev: Python + uvicorn directly
   - Containerized: Dockerfile (`backend/Dockerfile`, `frontend/Dockerfile`)
   - Orchestrated: `docker-compose.yml` (backend, frontend, volumes)
   - Production: VPS (DigitalOcean/GCP), Nginx reverse proxy, optional load balancer

---

## 5. Typical Use Cases

- Apna khud ka **private chat server** banane ke liye
- Friends / team ke beech **large files share** karne ke liye (self‑hosted)
- Android APK ke through **whitelabel messaging app** banana
- Learning project for:
  - FastAPI + MongoDB
  - Chunked file uploads / downloads
  - Docker + CI/CD + VPS deployment

---

## 6. Deployment Overview (Short)

- **Local:**
  - Backend: `python -m uvicorn backend.main:app --reload`
  - Frontend: `cd frontend && python app.py`
- **Docker (recommended):**
  - `docker-compose up --build` (backend + frontend + data volumes)
- **VPS / Cloud:**
  - Use Docker + docker‑compose on a server (e.g. DigitalOcean Droplet)
  - Configure MongoDB URI, SECRET_KEY, DATA_ROOT in `.env`
  - Optional Nginx reverse proxy for domain + HTTPS
- **Android:**
  - `cd frontend && flet build apk`

---

## 7. One‑Line Summary

> **HyperSend** ek Python‑based, self‑hosted **chat + large file transfer platform** hai jo **FastAPI + MongoDB backend** aur **Flet UI** ka use karke WhatsApp/Telegram‑style experience deta hai, jise aap Docker ke through kisi bhi VPS par deploy kar sakte ho aur Android APK ke roop me distribute kar sakte ho.
