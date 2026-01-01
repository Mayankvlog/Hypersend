# 🚀 Hypersend VPS Deployment Roadmap
## Current Architecture Analysis & Connection Issues

Based on analysis of your Hypersend project, here's the comprehensive roadmap to fix frontend-backend connectivity issues on your VPS.

---

## 📊 **Current Architecture Status**

### ✅ **What's Working**
- Docker containers are properly configured
- Nginx reverse proxy is set up correctly
- GitHub Actions deployment pipeline exists
- SSL certificates are configured (Let's Encrypt)
- Backend API endpoints are defined
- Flutter frontend is structured properly

### ❌ **Connection Issues Identified**
1. **Frontend-Backend Communication**: API calls not reaching backend
2. **CORS Configuration**: Possible cross-origin issues
3. **Environment Variables**: Missing proper VPS configuration
4. **Container Health**: Services may not be starting correctly
5. **Network Routing**: Nginx proxy configuration needs verification

---

## 🏗️ **Target Architecture**

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   User Browser  │───▶│     Nginx       │───▶│  Frontend (80)  │
│ (https://zaply  │    │   (Reverse      │    │   Flutter Web   │
│   .in.net)      │    │    Proxy)       │    │   Container     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │  Backend (8000)│
                       │  FastAPI        │
                       │  Container      │
                       └─────────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │   MongoDB       │
                       │   (27017)       │
                       │   Container     │
                       └─────────────────┘
```

---

## 🔧 **Step-by-Step Fix Roadmap**

### **Phase 1: Immediate Diagnostics (1-2 hours)**

#### 1.1 Check Current Container Status
```bash
# SSH into your VPS and run:
cd /hypersend/Hypersend
docker compose ps
docker compose logs --tail=50
```

#### 1.2 Test Individual Services
```bash
# Test backend directly
curl -I http://localhost:8000/health

# Test nginx proxy
curl -I https://zaply.in.net/health

# Test API endpoint
curl -I https://zaply.in.net/api/v1/health
```

#### 1.3 Check Network Configuration
```bash
# Verify Docker networks
docker network ls
docker network inspect hypersend_hypersend_network

# Check port bindings
netstat -tulpn | grep -E ':(80|443|8000|27017)'
```

### **Phase 2: Configuration Fixes (2-3 hours)**

#### 2.1 Update Environment Variables
Create `.env` file on VPS:
```bash
# On VPS at /hypersend/Hypersend/.env
API_BASE_URL=https://zaply.in.net/api/v1
SECRET_KEY=your-production-secret-key-here
MONGO_USER=your-mongo-user
MONGO_PASSWORD=your-mongo-password
DEBUG=False
CORS_ORIGINS=https://zaply.in.net,https://www.zaply.in.net
```

#### 2.2 Fix Frontend API Configuration
Update `frontend/lib/core/constants/api_constants.dart`:
```dart
class ApiConstants {
  static const String baseUrl = 'https://zaply.in.net/api/v1';
  static const String serverBaseUrl = 'https://zaply.in.net';
  static const bool validateCertificates = true;
  // ... rest of configuration
}
```

#### 2.3 Verify Nginx Configuration
Ensure `nginx.conf` has correct upstream servers:
```nginx
upstream backend {
    server hypersend_backend:8000;
    keepalive 32;
}

upstream frontend {
    server hypersend_frontend:80;
    keepalive 32;
}
```

### **Phase 3: Container Rebuild & Deploy (1-2 hours)**

#### 3.1 Force Rebuild Containers
```bash
# Stop all services
docker compose down

# Rebuild with latest code
docker compose build --no-cache

# Start services
docker compose up -d

# Wait for services to be healthy
sleep 30
docker compose ps
```

#### 3.2 Verify Health Checks
```bash
# Check each service health
docker compose exec backend curl -f http://localhost:8000/health
docker compose exec frontend curl -f http://localhost:80/health
```

### **Phase 4: API Connectivity Testing (1 hour)**

#### 4.1 Test Backend API Endpoints
```bash
# Test authentication endpoints
curl -X POST https://zaply.in.net/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"test123","name":"Test User"}'

# Test user endpoints
curl -X GET https://zaply.in.net/api/v1/users/me \
  -H "Authorization: Bearer YOUR_TOKEN"
```

#### 4.2 Test Frontend-Backend Connection
Open browser console and test:
```javascript
// Test API connectivity from browser
fetch('https://zaply.in.net/api/v1/health')
  .then(response => response.json())
  .then(data => console.log('API Test:', data))
  .catch(error => console.error('API Error:', error));
```

### **Phase 5: Production Optimization (1-2 hours)**

#### 5.1 SSL Certificate Verification
```bash
# Check SSL certificate status
certbot certificates
curl -I https://zaply.in.net

# Renew if needed
certbot renew --dry-run
```

#### 5.2 Performance Tuning
Update `docker-compose.yml` for production:
```yaml
services:
  backend:
    restart: unless-stopped
    environment:
      DEBUG: "False"
      WORKERS: "4"
    deploy:
      resources:
        limits:
          memory: 1G
```

---

## 🚨 **Critical Issues to Fix**

### **Issue #1: Frontend API Base URL**
**Problem**: Frontend may be pointing to wrong API URL
**Solution**: Update `ApiConstants.baseUrl` to `https://zaply.in.net/api/v1`

### **Issue #2: CORS Configuration**
**Problem**: Backend may not allow requests from production domain
**Solution**: Set `CORS_ORIGINS=https://zaply.in.net,https://www.zaply.in.net`

### **Issue #3: Container Health**
**Problem**: Services may be failing to start properly
**Solution**: Check logs and rebuild containers with `--no-cache`

### **Issue #4: Nginx Proxy**
**Problem**: Nginx may not be correctly proxying to backend
**Solution**: Verify upstream configuration and restart nginx

---

## 📋 **Deployment Checklist**

### **Pre-Deployment**
- [ ] Backup current database
- [ ] Save current container images
- [ ] Document current configuration
- [ ] Test on staging environment

### **Deployment Steps**
- [ ] Update environment variables
- [ ] Rebuild containers
- [ ] Verify service health
- [ ] Test API endpoints
- [ ] Check frontend connectivity
- [ ] Monitor error logs

### **Post-Deployment**
- [ ] Monitor application performance
- [ ] Check SSL certificate expiry
- [ ] Set up monitoring alerts
- [ ] Test user registration/login
- [ ] Verify file upload functionality

---

## 🔍 **Debugging Commands**

### **Container Diagnostics**
```bash
# View all container logs
docker compose logs -f

# Check specific service logs
docker compose logs backend
docker compose logs frontend
docker compose logs nginx

# Enter container for debugging
docker compose exec backend bash
docker compose exec frontend sh
```

### **Network Testing**
```bash
# Test internal Docker networking
docker compose exec backend curl http://frontend:80

# Test external connectivity
docker compose exec backend curl -I https://zaply.in.net

# Check DNS resolution
docker compose exec backend nslookup zaply.in.net
```

### **Database Verification**
```bash
# Test MongoDB connection
docker compose exec mongodb mongosh --eval "db.adminCommand('ping')"

# Check database collections
docker compose exec mongodb mongosh hypersend --eval "show collections"
```

---

## 📞 **Support & Monitoring**

### **Health Monitoring URLs**
- **Main Site**: https://zaply.in.net
- **Health Check**: https://zaply.in.net/health
- **API Health**: https://zaply.in.net/api/v1/health
- **API Docs**: https://zaply.in.net/docs

### **Log Monitoring**
```bash
# Real-time log monitoring
docker compose logs -f --tail=100

# Error-only monitoring
docker compose logs backend | grep ERROR
docker compose logs nginx | grep error
```

### **Performance Monitoring**
```bash
# Check resource usage
docker stats

# System performance
htop
iostat -x 1
```

---

## 🎯 **Success Criteria**

### **Immediate Goals (Today)**
- [ ] All containers running healthy
- [ ] Frontend loads at https://zaply.in.net
- [ ] API endpoints respond correctly
- [ ] User registration works
- [ ] File uploads functional

### **Short-term Goals (This Week)**
- [ ] Complete testing of all features
- [ ] Performance optimization
- [ ] Security audit completion
- [ ] Backup procedures implemented

### **Long-term Goals (This Month)**
- [ ] Monitoring system setup
- [ ] Automated testing pipeline
- [ ] Scalability improvements
- [ ] User feedback collection

---

## 🔄 **Maintenance Schedule**

### **Daily**
- Check container health status
- Monitor error logs
- Verify SSL certificates

### **Weekly**
- Update security patches
- Clean up unused containers
- Backup database

### **Monthly**
- Update dependencies
- Performance review
- Security audit

---

## 📈 **Next Steps After Fix**

1. **Set up CI/CD monitoring**
2. **Implement automated testing**
3. **Add performance monitoring**
4. **Create backup procedures**
5. **Document maintenance tasks**

---

---

## 🔐 **GitHub Actions Secrets Configuration**

Your GitHub repository has the following secrets configured for deployment:

### **📋 Current Secrets Status**
```yaml
# GitHub Actions Secrets (Repository Settings)
DOCKERHUB_TOKEN:      ✅ Configured (2 months ago)
DOCKERHUB_USERNAME:   ✅ Configured (2 months ago)
MONGO_PASSWORD:       ✅ Configured (last month)
MONGO_USER:           ✅ Configured (last month)
SECRET_KEY:           ✅ Configured (20 hours ago) - MOST RECENT
VPS_HOST:             ✅ Configured (2 months ago)
VPS_PASSWORD:         ✅ Configured (last month)
VPS_USER:             ✅ Configured (2 months ago)
```

### **🚀 Deployment Pipeline Flow**
```
GitHub Push → GitHub Actions → Docker Build → Push to DockerHub → SSH to VPS → Pull & Deploy
```

### **📝 Secret Usage in Deployment**
```yaml
# .github/workflows/deploy-backend.yml
- name: Deploy to VPS
  uses: appleboy/ssh-action@v1.2.0
  with:
    host: ${{ secrets.VPS_HOST }}           # Your VPS IP/Domain
    username: ${{ secrets.VPS_USER }}         # SSH username
    password: ${{ secrets.VPS_PASSWORD }}     # SSH password
    script: |
      cd /hypersend/Hypersend
      docker compose pull backend
      docker compose up -d backend
```

```yaml
# Docker Login in GitHub Actions
- name: Log in to Docker Hub
  uses: docker/login-action@v3
  with:
    username: ${{ secrets.DOCKERHUB_USERNAME }}
    password: ${{ secrets.DOCKERHUB_TOKEN }}
```

### **🔧 VPS Environment Variables Setup**
Create `/hypersend/Hypersend/.env` on your VPS:
```bash
# Database Configuration (from GitHub Secrets)
MONGO_USER=${MONGO_USER}
MONGO_PASSWORD=${MONGO_PASSWORD}

# Security Configuration (from GitHub Secrets)
SECRET_KEY=${SECRET_KEY}

# API Configuration
API_BASE_URL=https://zaply.in.net/api/v1
DEBUG=False
CORS_ORIGINS=https://zaply.in.net,https://www.zaply.in.net

# Production Settings
USE_MOCK_DB=False
EMAIL_SERVICE_ENABLED=False
```

### **🔄 How Secrets Connect VPS to GitHub**

1. **GitHub Actions** uses `VPS_HOST`, `VPS_USER`, `VPS_PASSWORD` to SSH into your VPS
2. **DockerHub Integration** uses `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN` to push/pull images
3. **Runtime Configuration** uses `MONGO_USER`, `MONGO_PASSWORD`, `SECRET_KEY` for application

### **⚠️ Security Best Practices**
- ✅ All secrets are properly configured
- ✅ SECRET_KEY was recently updated (20 hours ago)
- ✅ No secrets are exposed in repository code
- ⚠️ Consider using SSH keys instead of password for VPS access
- ⚠️ Rotate SECRET_KEY periodically for security

### **🛠️ Troubleshooting Secret Issues**

#### If deployment fails due to secrets:
```bash
# Test SSH connection manually
ssh ${VPS_USER}@${VPS_HOST}

# Verify DockerHub credentials
docker login -u ${DOCKERHUB_USERNAME}

# Check VPS environment variables
cd /hypersend/Hypersend
cat .env
```

#### Update secrets if needed:
1. Go to GitHub Repository → Settings → Secrets and variables → Actions
2. Click "New repository secret" 
3. Add/Update the secret value
4. Secrets are automatically available in next workflow run

---

## 🎯 **Complete Architecture Overview**

### **🏗️ Current vs Target Architecture**

#### **❌ Current State (Issues)**
```
User Browser → Nginx → ❌ Frontend Container
                    ↓
                 ❌ Backend Container (Not Connecting)
                    ↓
                 MongoDB Container
```

#### **✅ Target State (Working)**
```
User Browser
     ↓ (HTTPS)
Nginx Reverse Proxy
     ↓ (Proxy Pass)
┌─────────────┬─────────────┐
│ Frontend    │ Backend     │
│ Container   │ Container   │
│ (Port 80)   │ (Port 8000) │
└─────────────┴─────────────┘
     ↓                    ↓
Static Files         MongoDB
(Flutter Web)       (Port 27017)
```

### **📊 Service Dependencies**
```yaml
Services:
  nginx:
    depends_on: [backend, frontend]
    ports: ["80:80", "443:443"]
    
  frontend:
    depends_on: [backend]
    ports: ["3000:80"]
    
  backend:
    depends_on: [mongodb]
    ports: ["8000:8000"]
    environment: [MONGO_USER, MONGO_PASSWORD, SECRET_KEY]
    
  mongodb:
    ports: ["27018:27017"]
    environment: [MONGO_USER, MONGO_PASSWORD]
```

---

**🎉 By following this roadmap, you should have your Hypersend application fully functional on your VPS with proper frontend-backend connectivity!**

*Last Updated: January 2026*
*Version: 2.0 - Updated with GitHub Secrets Configuration*