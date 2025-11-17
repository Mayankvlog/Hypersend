# HyperSend Backend Deployment – Step-by-Step (GCP + Docker Hub + GitHub Actions, $300/90 Days)

Repo: <https://github.com/Mayankvlog/Hypersend>

Goal: **Deploy the FastAPI backend of HyperSend** to **Google Cloud Platform (Cloud Run)** using a Docker image stored on **Docker Hub**, built automatically via **GitHub Actions**, and keep it within your **$300 free credits (90 days)** while being able to grow towards many users.

> Important: $300 / 90 days is good for **development + early users** (even tens of thousands registered), but not for 100k users doing continuous 40GB uploads. We will set limits so you can run safely within the trial.

---

## 0. Prerequisites

Make sure you have:

1. **Accounts**
   - Google Cloud account (with free trial / $300 credits)
   - GitHub account
   - Docker Hub account
   - MongoDB Atlas account

2. **Local tools (optional but recommended)**
   - Git
   - Python 3.11+
   - Docker Desktop (for local testing)

3. **Project structure**
   - Repo already set up as `Mayankvlog/Hypersend` with:
     - `backend/` (FastAPI app + Dockerfile + requirements)
     - `frontend/` (Flet app)
     - `docker-compose.yml`, `nginx.conf`, `.env.example`, `README.md`

---

## Step 1 – Clone the Repository Locally (optional)

If not already cloned:

```bash
git clone https://github.com/Mayankvlog/Hypersend.git
cd Hypersend
cp .env.example .env
```

You can edit `.env` locally for testing (MongoDB URI, SECRET_KEY, etc.).

---

## Step 2 – Verify Backend Works Locally

1. Install backend dependencies:

   ```bash
   pip install -r backend/requirements.txt
   ```

2. Make sure MongoDB is running locally **or** you already have a MongoDB Atlas URI.

3. Run the backend from project root:

   ```bash
   python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
   ```

4. Open in browser:
   - `http://localhost:8000/`
   - `http://localhost:8000/health`

If this works, backend is ready to containerize and deploy.

---

## Step 3 – Create Docker Hub Repository

1. Go to <https://hub.docker.com> and log in.
2. Click **Create Repository**.
3. Fill:
   - **Repository name**: `hypersend-backend`
   - **Visibility**: Public (simpler for Cloud Run)
4. Note your image name:
   - `docker.io/<DOCKERHUB_USERNAME>/hypersend-backend:latest`

We will push images here from GitHub Actions.

---

## Step 4 – Set Up MongoDB Atlas (Database)

1. Go to <https://www.mongodb.com/atlas>.
2. Create a **Free Tier (M0)** cluster.
3. Create a **database user** (username + password).
4. Network Access:
   - For initial testing: allow IP `0.0.0.0/0` (open). Later, restrict to GCP IPs.
5. Get the **connection string** (MongoDB URI), for example:

   ```text
   mongodb+srv://<USER>:<PASSWORD>@cluster0.abcde.mongodb.net/hypersend
   ```

6. This will be used as `MONGODB_URI` in Cloud Run.
7. You can connect with MongoDB Compass using the same URI to inspect data.

---

## Step 5 – Configure GitHub Actions to Build & Push Docker Image

### 5.1 Add Docker Hub Secrets in GitHub

1. Open your repo: <https://github.com/Mayankvlog/Hypersend>
2. Go to **Settings → Security → Secrets and variables → Actions → New repository secret**.
3. Add two secrets:
   - `DOCKERHUB_USERNAME` → your Docker Hub username
   - `DOCKERHUB_TOKEN` → Docker Hub **access token** (create from Docker Hub → Account Settings → Security → New Access Token)

### 5.2 Add Workflow File

1. In your repo, create folder `.github/workflows` if it doesn’t exist.
2. Inside, create `deploy-dockerhub.yml` with:

   ```yaml
   name: build-and-push-backend

   on:
     push:
       branches: [ main ]
       paths:
         - 'backend/**'
         - 'docker-compose.yml'
         - '.env.example'

   jobs:
     build:
       runs-on: ubuntu-latest

       steps:
         - name: Checkout
           uses: actions/checkout@v4

         - name: Log in to Docker Hub
           run: echo "${{ secrets.DOCKERHUB_TOKEN }}" | docker login -u "${{ secrets.DOCKERHUB_USERNAME }}" --password-stdin

         - name: Build backend image
           run: |
             docker build -t ${{ secrets.DOCKERHUB_USERNAME }}/hypersend-backend:latest ./backend

         - name: Push backend image
           run: |
             docker push ${{ secrets.DOCKERHUB_USERNAME }}/hypersend-backend:latest
   ```

3. Commit and push:

   ```bash
   git add .github/workflows/deploy-dockerhub.yml
   git commit -m "Add Docker Hub CI workflow"
   git push origin main
   ```

4. Go to **GitHub → Actions** tab and ensure the workflow runs successfully.
5. Check Docker Hub: you should see `hypersend-backend:latest` image.

---

## Step 6 – Prepare GCP Project and Enable Free Credits

1. Go to <https://console.cloud.google.com> and log in.
2. Click **Select a project → New Project**:
   - Name: `hypersend-prod` (or anything)
3. Go to **Billing** and attach your free-trial billing account with **$300 / 90 days**.
4. Enable APIs:
   - Go to **APIs & Services → Library**
   - Enable **Cloud Run API**
   - Enable **Cloud Build API** (for future use)

---

## Step 7 – Deploy Backend to Cloud Run (Using Docker Hub Image)

### 7.1 Open Cloud Run

1. In GCP console, left menu → **Cloud Run**.
2. Click **Create Service**.

### 7.2 Configure Service (Basic)

1. **Service name**: `hypersend-backend`
2. **Region**: choose nearest to your users (e.g. `asia-south1` for India).
3. **Deployment platform**: Cloud Run (fully managed).
4. **Authentication**: Allow unauthenticated invocations (public API).

### 7.3 Choose Container Image

1. Under **Container image URL**, select:
   - `Deploy one revision from an existing container image`.
2. Enter image URL:

   ```text
   docker.io/<DOCKERHUB_USERNAME>/hypersend-backend:latest
   ```

### 7.4 Container Settings (Resources & Scaling)

Click **Container, Connections, Security** (or similar advanced settings):

1. **Container**:
   - Port: `8000`
   - CPU: **1 vCPU** (start) – upgrade later if needed.
   - Memory: **1–2 GB** (2 GB safer for larger traffic).

2. **Autoscaling**:
   - Min instances: `0` (cheapest, but cold start) or `1` (fast, but always-on cost).
   - Max instances: start with **20** (can increase later).
   - Concurrency: **50** (requests per instance – tune based on performance).

3. **Ingress**:
   - Allow all traffic.

### 7.5 Environment Variables (Very Important)

Add the following environment variables for the container:

- `MONGODB_URI` = `mongodb+srv://<USER>:<PASSWORD>@cluster0.abcde.mongodb.net/hypersend`
- `SECRET_KEY` = strong random string (e.g. from `python -c "import secrets;print(secrets.token_hex(32))"`)
- `API_HOST` = `0.0.0.0`
- `API_PORT` = `8000`
- `DEBUG` = `false`
- `DATA_ROOT` = `/data` (ephemeral; good for temp files only)

> For real large-file production, you should move storage to something like Google Cloud Storage or S3-compatible storage. For trial, keep file size and retention small.

4. Click **Create** and wait for deployment to finish.

### 7.6 Test the Deployed Backend

1. After deploy, Cloud Run will show a URL, like:

   ```text
   https://hypersend-backend-xxxxxx-uc.a.run.app
   ```

2. Test in browser or via curl:

   ```bash
   curl https://<CLOUD_RUN_URL>/
   curl https://<CLOUD_RUN_URL>/health
   ```

You should see the JSON status from the FastAPI app.

---

## Step 8 – Connect Frontend / Android APK to Cloud Run

In `frontend/app.py`, API URL is read from environment or fallback:

```python
API_URL = os.getenv("API_BASE_URL", os.getenv("API_URL", "http://localhost:8000"))
```

For production / APK:

1. Set `API_BASE_URL` to your Cloud Run URL, e.g.:

   ```bash
   # Example for local testing of env
   export API_BASE_URL="https://hypersend-backend-xxxxxx-uc.a.run.app"
   ```

2. For building Android APK (from project root):

   ```bash
   cd frontend
   flet build apk
   ```

Make sure before building APK, the API URL points to your Cloud Run backend.

---

## Step 9 – Tuning for $300 / 90 Days & Many Users

"Lakh users" = ~100k registered users. With $300 in 90 days, you must be careful about:

1. **File size & storage limits**
   - In `backend/config.py`, reduce:
     - `MAX_FILE_SIZE_BYTES` from 40GB to something like **1–2 GB** per file.
   - Implement per-user quota (e.g. `quota_limit` field in users collection).
   - Add cleanup logic / cron-like job to delete old files.

2. **Cloud Run scaling limits**
   - Concurrency: ~50 per instance (adjust by load testing).
   - Max instances: 20 to start, increase only if needed.
   - Min instances: 0 (cheaper, but slower first request) or 1.

3. **Monitor costs and performance**
   - Use **Cloud Monitoring / Logging** in GCP:
     - Track CPU, memory, request count, latency.
     - Check **network egress** (outgoing data – big cost).
   - In MongoDB Atlas, watch:
     - CPU, memory, IOPS
     - Storage usage (upgrade plan if needed).

4. **User behavior**
   - Lakh registered users, but usually only a fraction active at the same time.
   - With limited heavy uploads and decent tuning, your $300 should be enough for:
     - Many signups
     - Few thousand concurrent users
     - Moderate file transfer usage

If usage grows very fast (lots of big files, 24/7 traffic), you will need:

- Higher Cloud Run resource tiers
- Bigger MongoDB Atlas cluster (or self-hosted MongoDB on GCE)
- Dedicated object storage (Google Cloud Storage) for file uploads

---

## Step 10 – Quick Checklist

Use this as a final review:

- [ ] **Docker Hub**: repo `hypersend-backend` created
- [ ] **GitHub Secrets**: `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN` configured
- [ ] **GitHub Actions**: `deploy-dockerhub.yml` workflow added and passing
- [ ] **Docker Image**: `docker.io/<USER>/hypersend-backend:latest` exists
- [ ] **MongoDB Atlas**: cluster up, user created, `MONGODB_URI` copied
- [ ] **GCP Project**: created, billing with $300 credit enabled
- [ ] **Cloud Run**: service `hypersend-backend` deployed from Docker Hub
- [ ] **Env Vars**: `MONGODB_URI`, `SECRET_KEY`, `API_HOST`, `API_PORT`, `DEBUG`, `DATA_ROOT` set
- [ ] **Health Check**: `/` and `/health` working on Cloud Run URL
- [ ] **Frontend/APK**: `API_BASE_URL` updated to Cloud Run URL and APK built
- [ ] **Limits & Monitoring**: file size/quota limits set, Cloud Run & Atlas monitoring configured

With these steps completed, your HyperSend backend will be live on Google Cloud Run, built automatically from GitHub via Docker Hub, and ready to scale within your $300 / 90-day credit window.
---

## 11. Step-by-step Quick Guide (Hindi + English)

1. **Docker Hub setup**
   - Docker Hub pe account banao.
   - Naya repo banao: `hypersend-backend` (public rakhna easy hai).

2. **GitHub secrets add karo**
   - GitHub repo → **Settings → Secrets and variables → Actions**.
   - `DOCKERHUB_USERNAME` = tumhara Docker Hub username.
   - `DOCKERHUB_TOKEN` = Docker Hub access token.

3. **GitHub Actions workflow file banao**
   - Path: `.github/workflows/deploy-dockerhub.yml`.
   - Ye workflow backend ka Docker image banayega aur Docker Hub pe push karega jab bhi `main` branch pe push hoga.

4. **Backend Dockerfile check karo**
   - `backend/Dockerfile` me ensure karo ki `uvicorn backend.main:app --host 0.0.0.0 --port 8000` se app run ho raha hai.
   - Local me test: `docker build -t test-backend ./backend` aur `docker run -p 8000:8000 test-backend`.

5. **MongoDB Atlas cluster banao**
   - MongoDB Atlas pe free cluster (M0) banao.
   - User create karo, network access `0.0.0.0/0` (start ke liye).
   - Connection string copy karo (`MONGODB_URI`).

6. **GCP project + credits**
   - GCP console me new project banao (e.g. `hypersend-prod`).
   - Billing enable karo, $300 / 90 days trial activate karo.
   - **Cloud Run API** enable karo.

7. **Cloud Run service create karo (Docker Hub image se)**
   - Cloud Run → **Create Service**.
   - Image: `docker.io/<DOCKERHUB_USERNAME>/hypersend-backend:latest`.
   - Region: India ke paas (e.g. `asia-south1`).

8. **Cloud Run resources & scaling set karo**
   - CPU: 1 vCPU.
   - Memory: 1–2 GB.
   - Port: 8000.
   - Concurrency: around 50.
   - Min instances: 0 (cost bachane ke liye) ya 1 (fast response).
   - Max instances: 20–50 (taaki $300 credit jaldi na khatam ho).

9. **Environment variables set karo**
   - `MONGODB_URI` = Atlas URI.
   - `SECRET_KEY` = strong random string.
   - `API_HOST` = `0.0.0.0`.
   - `API_PORT` = `8000`.
   - `DEBUG` = `false`.

10. **Deploy aur test**
    - Cloud Run service deploy karo.
    - Jo URL mile, usko browser/curl se test karo: `/` aur `/health` endpoints.

11. **Frontend/APK ko connect karo**
    - Frontend/Android app me `API_URL` ko Cloud Run URL se replace karo.
    - Fir APK build karo (`flet build apk`).

12. **$300 / 90 days credit ko safe rakhne ke tips**
    - File size limit kam rakho (e.g. 1–2 GB per file, config.py me).
    - Per-user storage quota lagao.
    - Cloud Run max instances ko limit karo.
    - GCP console me Monitoring / Billing alert set karo.
