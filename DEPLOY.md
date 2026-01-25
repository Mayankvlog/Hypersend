# 🚀 Hypersend Vercel Deployment Guide

This guide will help you deploy your Hypersend application on Vercel step by step.

## 📋 Prerequisites

Before you begin, make sure you have:

- [x] Vercel account ([sign up here](https://vercel.com/signup))
- [x] GitHub account connected to Vercel
- [x] Hypersend project code pushed to GitHub
- [x] MongoDB Atlas account (for database)
- [x] SMTP credentials (for email services)

## 🏗️ Architecture Overview

Since Vercel is primarily a frontend platform, we'll deploy:
- **Frontend**: Flutter web app on Vercel
- **Backend**: FastAPI as serverless functions on Vercel
- **Database**: MongoDB Atlas (cloud database)
- **File Storage**: Vercel Blob or AWS S3

---

## 📝 Step 1: Prepare Your Project

### 1.1 Update Project Structure

Create the following structure in your project:

```
hypersend/
├── api/                    # Backend API routes (Vercel serverless)
│   ├── auth.py
│   ├── files.py
│   ├── users.py
│   └── index.py
├── frontend/               # Flutter web build
│   ├── build/
│   └── web/
├── public/                 # Static assets
├── vercel.json            # Vercel configuration
├── package.json           # Node.js dependencies
└── requirements.txt       # Python dependencies
```

### 1.2 Create Vercel Configuration

Create `vercel.json`:

```json
{
  "version": 2,
  "name": "hypersend",
  "builds": [
    {
      "src": "api/*.py",
      "use": "@vercel/python"
    },
    {
      "src": "frontend/build/web/**",
      "use": "@vercel/static"
    }
  ],
  "routes": [
    {
      "src": "/api/(.*)",
      "dest": "/api/$1"
    },
    {
      "src": "/(.*)",
      "dest": "/frontend/build/web/$1"
    }
  ],
  "env": {
    "PYTHON_VERSION": "3.9"
  },
  "functions": {
    "api/*.py": {
      "maxDuration": 30
    }
  }
}
```

### 1.3 Create package.json

Create `package.json`:

```json
{
  "name": "hypersend",
  "version": "1.0.0",
  "scripts": {
    "build": "echo 'Building frontend...' && cd frontend && flutter build web",
    "dev": "vercel dev"
  },
  "dependencies": {
    "@vercel/node": "^3.0.0"
  },
  "devDependencies": {
    "vercel": "^32.0.0"
  }
}
```

---

## 🐍 Step 2: Backend Setup for Vercel

### 2.1 Convert Backend to Serverless Functions

Create `api/index.py`:

```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os

app = FastAPI()

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure properly for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Import routes
from api.auth import router as auth_router
from api.files import router as files_router
from api.users import router as users_router

app.include_router(auth_router, prefix="/api/v1/auth", tags=["auth"])
app.include_router(files_router, prefix="/api/v1/files", tags=["files"])
app.include_router(users_router, prefix="/api/v1/users", tags=["users"])

@app.get("/")
async def root():
    return {"message": "Hypersend API"}

# For Vercel deployment
handler = app
```

### 2.2 Update Environment Variables

Create `api/config.py`:

```python
import os
from dotenv import load_dotenv

load_dotenv()

# Database Configuration
MONGODB_URL = os.getenv("MONGODB_URL", "mongodb+srv://hypersend:password@cluster.mongodb.net/hypersend")
MONGO_DATABASE = os.getenv("MONGO_DATABASE", "hypersend")

# JWT Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 28800

# File Upload Configuration
MAX_FILE_SIZE_BYTES = int(os.getenv("MAX_FILE_SIZE_BYTES", "42949672960"))  # 40GB
UPLOAD_TOKEN_EXPIRE_HOURS = int(os.getenv("UPLOAD_TOKEN_EXPIRE_HOURS", "480"))

# Email Configuration
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "noreply@zaply.in.net")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "your-app-password")
EMAIL_FROM = os.getenv("EMAIL_FROM", "noreply@zaply.in.net")

# File Storage (Vercel Blob or AWS S3)
STORAGE_TYPE = os.getenv("STORAGE_TYPE", "vercel_blob")
BLOB_READ_WRITE_TOKEN = os.getenv("BLOB_READ_WRITE_TOKEN", "")
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
AWS_S3_BUCKET = os.getenv("AWS_S3_BUCKET", "hypersend-files")
```

### 2.3 Update Database Connection

Create `api/database.py`:

```python
from motor.motor_asyncio import AsyncIOMotorClient
from .config import MONGODB_URL, MONGO_DATABASE

client = None
database = None

async def connect_to_mongo():
    global client, database
    client = AsyncIOMotorClient(MONGODB_URL)
    database = client[MONGO_DATABASE]
    print("Connected to MongoDB!")

async def close_mongo_connection():
    global client
    if client:
        client.close()
        print("Disconnected from MongoDB!")

def get_database():
    return database
```

---

## 📱 Step 3: Frontend Setup

### 3.1 Build Flutter Web

```bash
cd frontend

# Enable web support
flutter config --enable-web

# Build for production
flutter build web --release

# The build will be in frontend/build/web/
```

### 3.2 Update Flutter Configuration

Update `frontend/web/index.html`:

```html
<!DOCTYPE html>
<html>
<head>
  <title>Hypersend</title>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="icon" href="favicon.ico">
</head>
<body>
  <script src="main.dart.js" type="application/javascript"></script>
</body>
</html>
```

---

## 🗄️ Step 4: Database Setup (MongoDB Atlas)

### 4.1 Create MongoDB Atlas Account

1. Go to [MongoDB Atlas](https://www.mongodb.com/cloud/atlas)
2. Sign up for a free account
3. Create a new cluster (free tier is sufficient)

### 4.2 Configure Database

1. **Create Database User**:
   - Username: `hypersend`
   - Password: Generate a strong password
   - Database User Privileges: Read and write to any database

2. **Whitelist IP Address**:
   - Add `0.0.0.0/0` (allows access from anywhere, for Vercel)
   - Or add Vercel's IP ranges for better security

3. **Get Connection String**:
   - Click "Connect" → "Connect your application"
   - Copy the connection string
   - Format: `mongodb+srv://hypersend:PASSWORD@cluster.mongodb.net/hypersend`

---

## 📧 Step 5: Email Configuration

### 5.1 Gmail SMTP Setup

1. Enable 2-factor authentication on your Gmail account
2. Generate an App Password:
   - Go to Google Account settings
   - Security → 2-Step Verification → App passwords
   - Generate a new app password for "Mail"
   - Copy the 16-character password

### 5.2 Alternative: Use SendGrid

1. Sign up for [SendGrid](https://sendgrid.com/)
2. Create an API key
3. Verify your sender domain

---

## 📁 Step 6: File Storage Setup

### Option 1: Vercel Blob (Recommended)

1. Install Vercel CLI:
   ```bash
   npm i -g vercel
   ```

2. Create Blob store:
   ```bash
   vercel blob create
   ```

3. Get your read/write token from Vercel dashboard

### Option 2: AWS S3

1. Create AWS account
2. Create S3 bucket
3. Create IAM user with S3 access
4. Get access keys

---

## 🚀 Step 7: Deploy to Vercel

### 7.1 Connect to Vercel

1. **Install Vercel CLI**:
   ```bash
   npm i -g vercel
   ```

2. **Login to Vercel**:
   ```bash
   vercel login
   ```

3. **Initialize Project**:
   ```bash
   vercel
   ```

### 7.2 Configure Environment Variables

Set these in Vercel dashboard or via CLI:

```bash
# Database
vercel env add MONGODB_URL
vercel env add MONGO_DATABASE

# JWT
vercel env add SECRET_KEY

# Email
vercel env add SMTP_HOST
vercel env add SMTP_PORT
vercel env add SMTP_USERNAME
vercel env add SMTP_PASSWORD
vercel env add EMAIL_FROM

# File Storage
vercel env add STORAGE_TYPE
vercel env add BLOB_READ_WRITE_TOKEN
# or AWS credentials if using S3
```

### 7.3 Deploy

```bash
# Deploy to production
vercel --prod

# Or deploy to preview
vercel
```

---

## 🔧 Step 8: Post-Deployment Configuration

### 8.1 Custom Domain

1. Go to Vercel dashboard
2. Click "Domains"
3. Add your custom domain (e.g., `zaply.in.net`)
4. Configure DNS records as instructed

### 8.2 SSL Certificate

Vercel automatically provides SSL certificates for:
- `.vercel.app` domains
- Custom domains

### 8.3 Analytics and Monitoring

1. Enable Vercel Analytics in dashboard
2. Set up error monitoring (Sentry integration)
3. Configure uptime monitoring

---

## 📊 Step 9: Testing Your Deployment

### 9.1 Test API Endpoints

```bash
# Test health endpoint
curl https://your-domain.vercel.app/api/

# Test authentication
curl -X POST https://your-domain.vercel.app/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test@example.com","password":"password"}'
```

### 9.2 Test File Upload

```bash
# Test file upload
curl -X POST https://your-domain.vercel.app/api/v1/files/upload \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "file=@test.txt"
```

### 9.3 Test Frontend

Visit `https://your-domain.vercel.app` and test:
- User registration/login
- File upload/download
- All UI interactions

---

## 🛠️ Step 10: Troubleshooting

### Common Issues and Solutions

#### 1. **Serverless Function Timeout**
```json
// vercel.json
{
  "functions": {
    "api/*.py": {
      "maxDuration": 60  // Increase from default 10s
    }
  }
}
```

#### 2. **CORS Issues**
```python
# api/index.py
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://your-domain.vercel.app"],  # Be specific
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

#### 3. **Database Connection Issues**
- Check MongoDB Atlas IP whitelist
- Verify connection string format
- Ensure database user has correct permissions

#### 4. **File Upload Size Limits**
Vercel has a 4.5MB limit for request body. For larger files:

```python
# Use presigned URLs for large files
async def get_upload_url(filename: str):
    # Generate S3 or Blob presigned URL
    return {"upload_url": presigned_url}
```

#### 5. **Environment Variables Not Loading**
```python
import os
from dotenv import load_dotenv

load_dotenv()  # Make sure this is called
```

---

## 📈 Step 11: Performance Optimization

### 11.1 Caching

```python
from fastapi import responses

@app.get("/api/v1/files/{file_id}")
async def get_file(file_id: str):
    # Add caching headers
    return responses.JSONResponse(
        content={"file_url": file_url},
        headers={"Cache-Control": "public, max-age=3600"}
    )
```

### 11.2 Image Optimization

Use Vercel's built-in image optimization:

```html
<img src="/api/og" alt="Hypersend" />
```

### 11.3 Database Indexing

Create indexes in MongoDB:

```javascript
// MongoDB Atlas console
db.users.createIndex({ "email": 1 }, { unique: true })
db.files.createIndex({ "user_id": 1 })
db.files.createIndex({ "upload_date": -1 })
```

---

## 🔒 Step 12: Security Best Practices

### 12.1 Environment Variables

- Never commit secrets to Git
- Use Vercel's environment variables
- Rotate keys regularly

### 12.2 Rate Limiting

```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@app.post("/api/v1/auth/login")
@limiter.limit("5/minute")
async def login(request: Request):
    # Login logic
```

### 12.3 Input Validation

```python
from pydantic import BaseModel, validator

class UserLogin(BaseModel):
    email: str
    password: str
    
    @validator('email')
    def validate_email(cls, v):
        if not '@' in v:
            raise ValueError('Invalid email')
        return v
```

---

## 📝 Step 13: Maintenance and Updates

### 13.1 CI/CD Pipeline

Create `.github/workflows/deploy.yml`:

```yaml
name: Deploy to Vercel

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Setup Node.js
        uses: actions/setup-node@v2
        with:
          node-version: '18'
      - name: Install Vercel CLI
        run: npm install -g vercel
      - name: Deploy to Vercel
        run: vercel --prod --token=${{ secrets.VERCEL_TOKEN }}
```

### 13.2 Backup Strategy

- MongoDB Atlas automated backups
- File storage replication
- Regular database exports

### 13.3 Monitoring

- Vercel Analytics
- MongoDB Atlas monitoring
- Custom error logging
- Uptime monitoring

---

## 🎉 Conclusion

Your Hypersend application is now deployed on Vercel! Here's what you have:

✅ **Frontend**: Flutter web app hosted on Vercel
✅ **Backend**: FastAPI serverless functions
✅ **Database**: MongoDB Atlas cloud database
✅ **File Storage**: Vercel Blob or AWS S3
✅ **Email**: SMTP integration for notifications
✅ **SSL**: Automatic HTTPS certificates
✅ **Custom Domain**: Your own domain configured
✅ **Monitoring**: Analytics and error tracking

### Next Steps:

1. **Monitor Performance**: Use Vercel Analytics
2. **Scale Up**: Upgrade database and storage as needed
3. **Add Features**: Implement additional functionality
4. **Security Audit**: Regular security reviews
5. **User Feedback**: Collect and implement user suggestions

### Support Resources:

- [Vercel Documentation](https://vercel.com/docs)
- [MongoDB Atlas Docs](https://docs.mongodb.com/atlas)
- [Flutter Web Deployment](https://flutter.dev/docs/deployment/web)
- [FastAPI Documentation](https://fastapi.tiangolo.com)

Happy deploying! 🚀
