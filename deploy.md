# Hypersend Kubernetes Deployment Guide for GCP

## Table of Contents
1. [Kubernetes YAML File Line-by-Line Analysis](#kubernetes-yaml-file-line-by-line-analysis)
2. [Prerequisites](#prerequisites)
3. [GCP Setup](#gcp-setup)
4. [Build and Push Docker Images](#build-and-push-docker-images)
5. [Deploy to Kubernetes](#deploy-to-kubernetes)
6. [Post-Deployment Configuration](#post-deployment-configuration)
7. [Monitoring and Troubleshooting](#monitoring-and-troubleshooting)

---

## Kubernetes YAML File Line-by-Line Analysis

### Lines 1-8: Namespace Definition
```yaml
---
# Namespace
apiVersion: v1
kind: Namespace
metadata:
  name: hypersend
  labels:
    name: hypersend
```
**Purpose**: Creates a dedicated namespace called `hypersend` to isolate all application resources from other applications in the cluster.

**Key Components**:
- `apiVersion: v1`: Core Kubernetes API version
- `kind: Namespace`: Resource type for creating namespaces
- `metadata.name`: Unique identifier for the namespace
- `metadata.labels`: Key-value pairs for resource organization and selection

---

### Lines 11-69: ConfigMap for Application Configuration
```yaml
---
# ConfigMap for application configuration
apiVersion: v1
kind: ConfigMap
metadata:
  name: hypersend-config
  namespace: hypersend
data:
```
**Purpose**: Stores non-sensitive configuration data as key-value pairs that can be mounted as environment variables or files in containers.

#### Lines 18-33: API Configuration
```yaml
  # API Configuration
  SECRET_KEY: "Prod_Secret_Key_For_Zaply_2025_Secure_Fixed"
  ALGORITHM: "HS256"
  ACCESS_TOKEN_EXPIRE_MINUTES: "28800"
  REFRESH_TOKEN_EXPIRE_DAYS: "20"
  UPLOAD_TOKEN_EXPIRE_HOURS: "480"
  DATA_ROOT: "/data"
  UPLOADS_PATH: "/app/uploads"
  MAX_FILE_SIZE_BYTES: "42949672960"
  CHUNK_SIZE: "33554432"
  MAX_PARALLEL_CHUNKS: "4"
  FILE_RETENTION_HOURS: "0"
  DEBUG: "False"
  API_HOST: "0.0.0.0"
  API_PORT: "8000"
  API_BASE_URL: "https://zaply.in.net/api/v1"
```
**Configuration Details**:
- `SECRET_KEY`: JWT signing key (should be changed in production for security)
- `ALGORITHM`: JWT encryption algorithm (HS256 for HMAC-SHA256)
- `ACCESS_TOKEN_EXPIRE_MINUTES`: Access token lifetime (28800 = 8 hours)
- `REFRESH_TOKEN_EXPIRE_DAYS`: Refresh token lifetime (20 days)
- `UPLOAD_TOKEN_EXPIRE_HOURS`: Upload token lifetime (480 = 20 days)
- `MAX_FILE_SIZE_BYTES`: Maximum file size (42949672960 = 40GB)
- `CHUNK_SIZE`: File upload chunk size (33554432 = 32MB)
- `MAX_PARALLEL_CHUNKS`: Concurrent upload chunks (4)
- `FILE_RETENTION_HOURS`: File auto-deletion timer (0 = disabled)
- `DEBUG`: Debug mode flag (False for production)
- `API_BASE_URL`: Production API endpoint URL

#### Lines 35-36: CORS Configuration
```yaml
  # CORS Configuration
  ALLOWED_ORIGINS: "https://zaply.in.net,http://localhost:3000,http://127.0.0.1:3000"
```
**Purpose**: Defines which origins are allowed to make cross-origin requests to the API.

#### Lines 38-41: Rate Limiting & Security
```yaml
  # Rate Limiting & Security
  RATE_LIMIT_PER_USER: "100"
  RATE_LIMIT_WINDOW_SECONDS: "60"
  USE_MOCK_DB: "False"
```
**Settings**:
- `RATE_LIMIT_PER_USER`: Maximum requests per user per time window
- `RATE_LIMIT_WINDOW_SECONDS`: Time window for rate limiting (60 seconds)
- `USE_MOCK_DB`: Database mock flag (False for production database)

#### Lines 43-51: Email Configuration
```yaml
  # Email Configuration
  ENABLE_EMAIL: "true"
  ENABLE_PASSWORD_RESET: "true"
  SMTP_HOST: "smtp.gmail.com"
  SMTP_PORT: "587"
  SMTP_USERNAME: "noreply@zaply.in.net"
  SMTP_USE_TLS: "true"
  EMAIL_FROM: "noreply@zaply.in.net"
  SENDER_NAME: "Zaply Support"
```
**Email Service Settings**:
- `ENABLE_EMAIL`: Toggle email functionality
- `ENABLE_PASSWORD_RESET`: Enable password reset emails
- `SMTP_*`: Gmail SMTP server configuration
- `EMAIL_FROM`: Default sender email address

#### Lines 53-69: Nginx Configuration
```yaml
  # Nginx Configuration
  NGINX_ALLOW_UNSAFE_SSL: "true"
  NGINX_API_BASE_URL: "https://zaply.in.net/api/v1"
  NGINX_API_HOST: "0.0.0.0"
  NGINX_API_KEY: "hypersend_secure_api_key"
  NGINX_API_SECRET: "hypersend_secure_api_secret"
  NGINX_PROXY_READ_TIMEOUT: "3600"
  NGINX_PROXY_SEND_TIMEOUT: "3600"
  NGINX_PROXY_CONNECT_TIMEOUT: "300"
  NGINX_CLIENT_BODY_TIMEOUT: "3600"
  NGINX_CLIENT_MAX_BODY_SIZE: "45G"
  NGINX_ERROR_PAGE_TIMEOUT: "30"
  NGINX_MAX_RETRIES: "7"
  NGINX_RETRY_DELAY: "5"
  DOMAIN_NAME: "zaply.in.net"
  SSL_CERT_PATH: "/etc/letsencrypt/live/zaply.in.net/fullchain.pem"
  SSL_KEY_PATH: "/etc/letsencrypt/private/privkey.pem"
```
**Nginx Settings**:
- Various timeout and size limits for large file uploads
- `DOMAIN_NAME`: Primary domain for SSL certificates
- SSL certificate paths for Let's Encrypt

---

### Lines 72-85: Secrets for Sensitive Data
```yaml
---
# Secrets for sensitive data
apiVersion: v1
kind: Secret
metadata:
  name: hypersend-secrets
  namespace: hypersend
type: Opaque
data:
  # MongoDB credentials (base64 encoded)
  MONGO_USER: aHlwZXJzZW5k  # hypersend
  MONGO_PASSWORD: aHlwZXJzZW5kX3NlY3VyZV9wYXNzd29yZA==  # hypersend_secure_password
  MONGO_INITDB_DATABASE: aHlwZXJzZW5k  # hypersend
  # SMTP password (base64 encoded)
  SMTP_PASSWORD: ZHVtbXlfYXBwX3Bhc3N3b3JkX2NvbmZpZ3VyZV9pbl9lbnY=  # dummy_app_password_configure_in_env
```
**Purpose**: Stores sensitive data in base64-encoded format, automatically decoded by Kubernetes when mounted in containers.

**Secret Details (Base64 Decoded)**:
- `MONGO_USER`: `hypersend`
- `MONGO_PASSWORD`: `hypersend_secure_password`
- `MONGO_INITDB_DATABASE`: `hypersend`
- `SMTP_PASSWORD`: `dummy_app_password_configure_in_env` (should be updated)

---

### Lines 88-415: Nginx Configuration ConfigMap
```yaml
---
# Nginx Configuration ConfigMap
apiVersion: v1
kind: ConfigMap
metadata:
  name: nginx-configmap
  namespace: hypersend
data:
  nginx.conf: |
```
**Purpose**: Contains the complete nginx configuration for reverse proxy, load balancing, SSL termination, and security headers.

#### Lines 96-106: Basic Nginx Settings
```nginx
    # NGINX Configuration for Zaply
    user nginx;
    worker_processes auto;
    error_log /var/log/nginx/error.log warn;
    pid /var/run/nginx.pid;
```
**Configuration**: Basic nginx process settings and logging configuration.

#### Lines 102-106: Events Block
```nginx
    events {
        worker_connections 4096;
        use epoll;
        multi_accept on;
    }
```
**Settings**: Connection handling configuration for high performance.

#### Lines 108-151: HTTP Configuration
```nginx
    http {
        include /etc/nginx/mime.types;
        default_type application/octet-stream;
        # ... logging, timeouts, gzip, security headers
    }
```
**Features**:
- MIME type handling
- Custom log format
- Performance optimizations (sendfile, tcp_nopush)
- Gzip compression
- Security headers (X-Frame-Options, X-Content-Type-Options)

#### Lines 158-170: Upstream Servers
```nginx
    upstream backend {
        server backend:8000 max_fails=5 fail_timeout=30s weight=100;
        keepalive 64;
    }
    upstream frontend {
        server frontend:80 max_fails=3 fail_timeout=30s weight=100;
        keepalive 32;
    }
```
**Purpose**: Defines backend and frontend server pools with health checks and connection pooling.

#### Lines 175-180: Rate Limiting Zones
```nginx
    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=100r/m;
    limit_req_zone $binary_remote_addr zone=general_limit:10m rate=200r/m;
    limit_req_zone $binary_remote_addr zone=upload_limit:10m rate=20r/s;
    limit_req_zone $binary_remote_addr zone=auth_limit:10m rate=6r/m;
```
**Rate Limits**:
- API: 100 requests/minute
- General: 200 requests/minute
- Upload: 20 requests/second
- Auth: 6 requests/minute

#### Lines 182-191: CORS Origin Mapping
```nginx
    map $http_origin $allowed_origin {
        default "";
        "~^https://zaply\.in\.net$" "https://zaply.in.net";
        "~^https://www\.zaply\.in\.net$" "https://www.zaply.in.net";
        "~^http://localhost:8000$" "http://localhost:8000";
        "~^http://localhost:3000$" "http://localhost:3000";
        "~^http://localhost(:[0-9]+)?$" $http_origin;
        "~^http://127\.0\.0\.1(:[0-9]+)?$" $http_origin;
    }
```
**Security**: Restricts CORS to authorized origins only.

#### Lines 194-207: HTTP to HTTPS Redirect
```nginx
    server {
        listen 80;
        listen [::]:80;
        server_name zaply.in.net www.zaply.in.net;
        
        location / {
            return 301 https://$server_name$request_uri;
        }
        
        location /.well-known/acme-challenge/ {
            root /var/www/certbot;
        }
    }
```
**Purpose**: Redirects all HTTP traffic to HTTPS for the main domain, with exception for Let's Encrypt challenges.

#### Lines 210-258: Default HTTP Server
```nginx
    server {
        listen 80 default_server;
        listen [::]:80 default_server;
        server_name _;
        # ... health endpoint, API proxy, frontend proxy
    }
```
**Functionality**: Handles default HTTP traffic for testing and non-SSL domains.

#### Lines 262-414: HTTPS Production Server
```nginx
    server {
        listen 443 ssl http2;
        listen [::]:443 ssl http2;
        server_name zaply.in.net www.zaply.in.net;
        
        # SSL Configuration
        ssl_certificate /etc/letsencrypt/live/zaply.in.net/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/private/privkey.pem;
        # ... security headers, location blocks
    }
```
**Features**:
- SSL/TLS termination with HTTP/2
- Modern SSL configuration (TLS 1.2/1.3)
- HSTS and security headers
- Specialized location blocks for different endpoints
- CORS handling for API endpoints

---

### Lines 418-514: Persistent Volume Claims
```yaml
---
# Persistent Volume Claims
apiVersion: v1
kind: PersistentVolumeClaim
```
**Purpose**: Defines storage requirements for persistent data that survives pod restarts.

#### PVC Details:
1. **mongodb-data-pvc** (Lines 419-430): 10Gi for MongoDB database storage
2. **mongodb-config-pvc** (Lines 432-444): 1Gi for MongoDB configuration
3. **data-pvc** (Lines 446-458): 20Gi for application data
4. **uploads-pvc** (Lines 460-472): 10Gi for file uploads
5. **letsencrypt-certs-pvc** (Lines 474-486): 1Gi for SSL certificates
6. **letsencrypt-lib-pvc** (Lines 488-500): 1Gi for Let's Encrypt library
7. **nginx-cache-pvc** (Lines 502-514): 2Gi for nginx cache

**Total Storage**: 44Gi across 7 PVCs

---

### Lines 517-616: MongoDB Deployment and Service
```yaml
---
# MongoDB Deployment and Service
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mongodb
  namespace: hypersend
```
**Purpose**: Deploys MongoDB database with authentication and persistence.

#### Deployment Configuration (Lines 519-600):
- **Replicas**: 1 (single instance)
- **Image**: mongo:7.0
- **Resources**: 512Mi-1Gi memory, 250m-500m CPU
- **Authentication**: Enabled with username/password from secrets
- **Storage**: Uses mongodb-data-pvc and mongodb-config-pvc
- **Health Checks**: Liveness and readiness probes using mongosh

#### Service Configuration (Lines 603-616):
- **Type**: ClusterIP (internal only)
- **Port**: 27017
- **Selector**: app: mongodb

---

### Lines 619-720: Backend Deployment and Service
```yaml
---
# Backend Deployment and Service
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend
```
**Purpose**: Deploys the Hypersend backend API service.

#### Deployment Configuration (Lines 621-704):
- **Replicas**: 2 (high availability)
- **Image**: hypersend/backend:latest
- **Resources**: 512Mi-1Gi memory, 250m-500m CPU
- **Environment**: ConfigMap + secrets for configuration
- **Storage**: Mounts data and uploads volumes
- **Health Checks**: HTTP health endpoint on port 8000

#### Service Configuration (Lines 707-720):
- **Type**: ClusterIP (internal)
- **Port**: 8000
- **Selector**: app: backend

---

### Lines 723-792: Frontend Deployment and Service
```yaml
---
# Frontend Deployment and Service
apiVersion: apps/v1
kind: Deployment
metadata:
  name: frontend
```
**Purpose**: Deploys the frontend web application.

#### Deployment Configuration (Lines 725-776):
- **Replicas**: 2 (high availability)
- **Image**: hypersend/frontend:latest
- **Resources**: 128Mi-256Mi memory, 100m-200m CPU
- **Environment**: API_BASE_URL from ConfigMap
- **Health Checks**: HTTP health endpoint on port 80

#### Service Configuration (Lines 779-792):
- **Type**: ClusterIP (internal)
- **Port**: 80
- **Selector**: app: frontend

---

### Lines 795-910: Nginx Deployment and Service
```yaml
---
# Nginx Deployment and Service
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
```
**Purpose**: Deploys nginx reverse proxy with SSL termination.

#### Deployment Configuration (Lines 797-889):
- **Replicas**: 2 (high availability)
- **Image**: nginx:alpine
- **Resources**: 128Mi-256Mi memory, 100m-200m CPU
- **Startup Script**: Auto-generates self-signed certificates if none exist
- **Storage**: Mounts nginx config, certificates, and cache volumes
- **Health Checks**: HTTP health endpoint on port 80

#### Service Configuration (Lines 893-910):
- **Type**: LoadBalancer (external access)
- **Ports**: 80 (HTTP) and 443 (HTTPS)
- **Selector**: app: nginx

---

### Lines 913-969: Ingress for External Access (Optional)
```yaml
---
# Ingress for external access (optional)
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: hypersend-ingress
  namespace: hypersend
```
**Purpose**: Provides external HTTP/HTTPS access using nginx ingress controller.

#### Ingress Configuration:
- **Annotations**: SSL, rate limiting, and proxy settings
- **TLS**: Automatic SSL certificate management with cert-manager
- **Rules**: Routes /api to backend, / to frontend
- **Hosts**: zaply.in.net and www.zaply.in.net

---

## Prerequisites

### GCP Account Setup
1. Create GCP account with billing enabled
2. Install Google Cloud SDK
3. Install kubectl
4. Install Docker

### Required Tools Installation
```bash
# Install Google Cloud SDK (Linux/Mac)
curl https://sdk.cloud.google.com | bash
exec -l $SHELL

# Install kubectl
gcloud components install kubectl

# Install Docker (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install docker.io
sudo usermod -aG docker $USER

# Verify installations
gcloud version
kubectl version --client
docker --version
```

### Authentication
```bash
# Authenticate with GCP
gcloud auth login
gcloud auth application-default login

# Set your project
gcloud config set project YOUR_PROJECT_ID

# Enable required APIs
gcloud services enable container.googleapis.com
gcloud services enable artifactregistry.googleapis.com
gcloud services enable cloudbuild.googleapis.com
```

---

## GCP Setup

### 1. Create GKE Cluster
```bash
# Create a production-ready GKE cluster
gcloud container clusters create hypersend-cluster \
  --zone=us-central1-a \
  --num-nodes=3 \
  --machine-type=e2-standard-2 \
  --disk-size=100GB \
  --enable-autoscaling \
  --min-nodes=2 \
  --max-nodes=5 \
  --enable-autorepair \
  --enable-autoupgrade \
  --cluster-version=latest \
  --release-channel=stable
```

**Cluster Configuration Details**:
- **Zone**: us-central1-a (choose your preferred region)
- **Nodes**: 3 initial nodes, autoscaling 2-5 nodes
- **Machine Type**: e2-standard-2 (2 vCPUs, 8GB RAM)
- **Disk Size**: 100GB SSD per node
- **Features**: Auto-repair, auto-upgrade, stable release channel

### 2. Configure kubectl
```bash
# Get cluster credentials
gcloud container clusters get-credentials hypersend-cluster --zone=us-central1-a

# Verify cluster connection
kubectl cluster-info

# View cluster nodes
kubectl get nodes
```

### 3. Verify Cluster Resources
```bash
# Check cluster capacity
kubectl describe nodes

# Check available storage classes
kubectl get storageclass

# Verify network policies
kubectl get networkpolicy --all-namespaces
```

---

## Build and Push Docker Images

### 1. Create Backend Dockerfile
Create `backend/Dockerfile`:
```dockerfile
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user
RUN useradd --create-home --shell /bin/bash app \
    && chown -R app:app /app
USER app

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Start command
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### 2. Create Frontend Dockerfile
Create `frontend/Dockerfile`:
```dockerfile
# Build stage
FROM node:18-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

COPY . .
RUN npm run build

# Production stage
FROM nginx:alpine

# Copy built application
COPY --from=builder /app/build /usr/share/nginx/html

# Copy nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Create non-root user
RUN addgroup -g 1001 -S nginx
RUN adduser -S nginx -u 1001

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost/health || exit 1

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
```

### 3. Enable Artifact Registry
```bash
# Enable Artifact Registry API
gcloud services enable artifactregistry.googleapis.com

# Create Docker repository
gcloud artifacts repositories create hypersend-repo \
  --repository-format=docker \
  --location=us-central1 \
  --description="Hypersend Docker images"
```

### 4. Configure Docker Authentication
```bash
# Configure Docker to use GCP credentials
gcloud auth configure-docker us-central1-docker.pkg.dev

# Verify authentication
docker pull us-central1-docker.pkg.dev/$PROJECT_ID/hypersend-repo/test:latest
```

### 5. Build and Push Backend Image
```bash
# Navigate to backend directory
cd backend

# Build backend image
docker build -t us-central1-docker.pkg.dev/$PROJECT_ID/hypersend-repo/backend:latest .

# Push to Artifact Registry
docker push us-central1-docker.pkg.dev/$PROJECT_ID/hypersend-repo/backend:latest

# Verify image
gcloud artifacts docker images list us-central1-docker.pkg.dev/$PROJECT_ID/hypersend-repo --filter="backend"
```

### 6. Build and Push Frontend Image
```bash
# Navigate to frontend directory
cd frontend

# Build frontend image
docker build -t us-central1-docker.pkg.dev/$PROJECT_ID/hypersend-repo/frontend:latest .

# Push to Artifact Registry
docker push us-central1-docker.pkg.dev/$PROJECT_ID/hypersend-repo/frontend:latest

# Verify image
gcloud artifacts docker images list us-central1-docker.pkg.dev/$PROJECT_ID/hypersend-repo --filter="frontend"
```

### 7. Update Kubernetes YAML with Image Paths
```bash
# Replace image references in kubernetes.yaml
sed -i "s|hypersend/backend:latest|us-central1-docker.pkg.dev/$PROJECT_ID/hypersend-repo/backend:latest|g" kubernetes.yaml
sed -i "s|hypersend/frontend:latest|us-central1-docker.pkg.dev/$PROJECT_ID/hypersend-repo/frontend:latest|g" kubernetes.yaml

# Verify changes
grep "image:" kubernetes.yaml
```

---

## Deploy to Kubernetes

### 1. Deploy Infrastructure Components
```bash
# Apply all Kubernetes manifests
kubectl apply -f kubernetes.yaml

# Or deploy step by step for better control:
kubectl apply -f <(sed -n '1,8p' kubernetes.yaml)  # Namespace
kubectl apply -f <(sed -n '11,69p' kubernetes.yaml) # ConfigMap
kubectl apply -f <(sed -n '72,85p' kubernetes.yaml) # Secrets
kubectl apply -f <(sed -n '88,415p' kubernetes.yaml) # Nginx ConfigMap
```

### 2. Deploy Storage Components
```bash
# Deploy Persistent Volume Claims
kubectl apply -f <(sed -n '418,514p' kubernetes.yaml)

# Wait for PVCs to be bound
kubectl get pvc -n hypersend -w
```

### 3. Deploy Database
```bash
# Deploy MongoDB
kubectl apply -f <(sed -n '517,616p' kubernetes.yaml)

# Wait for MongoDB to be ready
kubectl wait --for=condition=ready pod -l app=mongodb -n hypersend --timeout=300s

# Verify MongoDB deployment
kubectl logs -l app=mongodb -n hypersend
```

### 4. Deploy Application Services
```bash
# Deploy backend
kubectl apply -f <(sed -n '619,720p' kubernetes.yaml)

# Deploy frontend
kubectl apply -f <(sed -n '723,792p' kubernetes.yaml)

# Deploy nginx
kubectl apply -f <(sed -n '795,910p' kubernetes.yaml)

# Wait for all pods to be ready
kubectl wait --for=condition=ready pod -l app=backend -n hypersend --timeout=300s
kubectl wait --for=condition=ready pod -l app=frontend -n hypersend --timeout=300s
kubectl wait --for=condition=ready pod -l app=nginx -n hypersend --timeout=300s
```

### 5. Deploy Ingress (Optional)
```bash
# Install nginx ingress controller if not present
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm repo update
helm install ingress-nginx ingress-nginx/ingress-nginx --namespace ingress-nginx --create-namespace

# Deploy ingress
kubectl apply -f <(sed -n '913,969p' kubernetes.yaml)
```

### 6. Verify Deployment
```bash
# Check all resources in hypersend namespace
kubectl get all -n hypersend

# Check pod status
kubectl get pods -n hypersend -w

# Check services
kubectl get services -n hypersend

# Check PVCs
kubectl get pvc -n hypersend

# Check ingress
kubectl get ingress -n hypersend
```

### 7. Get External Access Information
```bash
# Get LoadBalancer external IP
kubectl get service nginx -n hypersend -o wide

# Get external IP (wait for assignment)
EXTERNAL_IP=$(kubectl get service nginx -n hypersend -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
echo "External IP: $EXTERNAL_IP"

# Test access
curl -I http://$EXTERNAL_IP/health
curl -I https://$EXTERNAL_IP/health
```

---

## Post-Deployment Configuration

### 1. DNS Configuration
```bash
# Get the external IP
EXTERNAL_IP=$(kubectl get service nginx -n hypersend -o jsonpath='{.status.loadBalancer.ingress[0].ip}')

# Configure your domain DNS records
# A record: zaply.in.net -> $EXTERNAL_IP
# A record: www.zaply.in.net -> $EXTERNAL_IP

# Verify DNS propagation
nslookup zaply.in.net
dig zaply.in.net
```

### 2. SSL Certificate Setup with Let's Encrypt
```bash
# Install cert-manager
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml

# Create ClusterIssuer for Let's Encrypt
cat > cluster-issuer.yaml << EOF
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@zaply.in.net
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: nginx
EOF

kubectl apply -f cluster-issuer.yaml

# Verify cert-manager
kubectl get pods -n cert-manager
kubectl get clusterissuer
```

### 3. Update Production Secrets
```bash
# Generate new secure values
NEW_SECRET_KEY=$(openssl rand -base64 32)
NEW_MONGO_PASSWORD=$(openssl rand -base64 16)
NEW_SMTP_PASSWORD="your_real_gmail_app_password"

# Update ConfigMap with new secret key
kubectl patch configmap hypersend-config -n hypersend -p='{"data":{"SECRET_KEY":"'$(echo $NEW_SECRET_KEY)'"}}'

# Update secrets with secure values
kubectl patch secret hypersend-secrets -n hypersend -p='{"data":{"MONGO_PASSWORD":"'$(echo -n $NEW_MONGO_PASSWORD | base64)'","SMTP_PASSWORD":"'$(echo -n $NEW_SMTP_PASSWORD | base64)'"}}'

# Restart deployments to pick up new secrets
kubectl rollout restart deployment/backend -n hypersend
kubectl rollout restart deployment/mongodb -n hypersend
```

### 4. Configure Monitoring
```bash
# Install Prometheus and Grafana (optional)
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

# Install Prometheus
helm install prometheus prometheus-community/kube-prometheus-stack --namespace monitoring --create-namespace

# Access Grafana
kubectl port-forward -n monitoring svc/prometheus-grafana 3000:80
# Username: admin, Password: get with: kubectl get secret --namespace monitoring prometheus-grafana -o jsonpath="{.data.admin-password}" | base64 --decode
```

---

## Monitoring and Troubleshooting

### 1. Health Checks and Monitoring
```bash
# Check overall cluster health
kubectl get componentstatuses
kubectl get nodes -o wide

# Monitor pod status
kubectl get pods -n hypersend -o wide
kubectl top pods -n hypersend

# Check resource usage
kubectl describe nodes
kubectl top nodes
```

### 2. Log Management
```bash
# View backend logs
kubectl logs -f deployment/backend -n hypersend

# View frontend logs
kubectl logs -f deployment/frontend -n hypersend

# View nginx logs
kubectl logs -f deployment/nginx -n hypersend

# View MongoDB logs
kubectl logs -f deployment/mongodb -n hypersend

# View all logs with labels
kubectl logs -n hypersend -l app=backend --tail=100
```

### 3. Debugging Common Issues
```bash
# Port forward to local testing
kubectl port-forward service/backend 8000:8000 -n hypersend &
kubectl port-forward service/frontend 3000:80 -n hypersend &

# Execute into containers
kubectl exec -it deployment/backend -n hypersend -- /bin/bash
kubectl exec -it deployment/mongodb -n hypersend -- mongosh

# Check events
kubectl get events -n hypersend --sort-by='.lastTimestamp'

# Describe resources
kubectl describe pod -l app=backend -n hypersend
kubectl describe service nginx -n hypersend
kubectl describe pvc -n hypersend
```

### 4. Performance Testing
```bash
# Test health endpoints
curl -w "@curl-format.txt" -o /dev/null -s http://EXTERNAL_IP/health
curl -w "@curl-format.txt" -o /dev/null -s https://EXTERNAL_IP/health

# Test API endpoints
curl -X GET http://EXTERNAL_IP/api/health
curl -X POST http://EXTERNAL_IP/api/v1/files/upload -F "file=@test.txt"

# Load testing with Apache Bench
ab -n 1000 -c 10 http://EXTERNAL_IP/health
```

### 5. Backup and Recovery
```bash
# Backup MongoDB
kubectl exec -it deployment/mongodb -n hypersend -- mongodump --out /backup/$(date +%Y%m%d)

# Backup PVCs
kubectl get pvc -n hypersend -o yaml > pvc-backup.yaml

# Create backup scripts
cat > backup-script.sh << 'EOF'
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
kubectl exec -it deployment/mongodb -n hypersend -- mongodump --out /backup/$DATE
kubectl cp hypersend/mongodb-pod:/backup/$DATE ./backups/
EOF
```

### 6. Scaling Operations
```bash
# Scale backend
kubectl scale deployment backend --replicas=3 -n hypersend

# Scale frontend
kubectl scale deployment frontend --replicas=3 -n hypersend

# Scale nginx
kubectl scale deployment nginx --replicas=3 -n hypersend

# Enable autoscaling
kubectl autoscale deployment backend --cpu-percent=70 --min=2 --max=10 -n hypersend
kubectl autoscale deployment frontend --cpu-percent=70 --min=2 --max=5 -n hypersend

# Check autoscaler status
kubectl get hpa -n hypersend
```

---

## Production Checklist

### Security
- [ ] Update SECRET_KEY in ConfigMap with unique value
- [ ] Configure real SMTP password and test email functionality
- [ ] Set up proper domain DNS with A records
- [ ] Configure SSL certificates with Let's Encrypt
- [ ] Review and tighten network policies
- [ ] Enable GCP IAM best practices
- [ ] Set up audit logging

### Performance
- [ ] Configure horizontal pod autoscaling
- [ ] Set up resource monitoring with Prometheus
- [ ] Test load handling and optimize resource limits
- [ ] Configure CDN for static assets if needed
- [ ] Optimize database queries and indexing

### Reliability
- [ ] Set up automated backups for MongoDB
- [ ] Configure multi-zone deployment if available
- [ ] Set up disaster recovery procedures
- [ ] Configure alerting for critical failures
- [ ] Test failover scenarios

### Operations
- [ ] Set up log aggregation (Stackdriver/Cloud Logging)
- [ ] Configure CI/CD pipeline for automated deployments
- [ ] Set up monitoring dashboards
- [ ] Create runbooks for common issues
- [ ] Schedule regular security updates

---

## Cleanup and Cost Management

### Remove All Resources
```bash
# Delete namespace and all resources
kubectl delete namespace hypersend

# Delete cluster
gcloud container clusters delete hypersend-cluster --zone=us-central1-a

# Delete Artifact Registry repository
gcloud artifacts repositories delete hypersend-repo --location=us-central1
```

### Cost Optimization
```bash
# Resize cluster for development
gcloud container clusters resize hypersend-cluster --node-pool=default-pool --size=1 --zone=us-central1-a

# Use preemptible nodes for non-critical workloads
gcloud container clusters create hypersend-cluster \
  --preemptible \
  --min-nodes=0 \
  --max-nodes=3

# Set up cluster autoscaling for cost efficiency
gcloud container clusters update hypersend-cluster \
  --enable-autoscaling \
  --min-nodes=1 \
  --max-nodes=5 \
  --zone=us-central1-a
```

---

## Conclusion

This deployment guide provides a comprehensive, production-ready setup for the Hypersend file-sharing application on Google Kubernetes Engine. The configuration includes:

- **High Availability**: Multiple replicas and autoscaling
- **Security**: SSL/TLS, secrets management, network policies
- **Performance**: Optimized nginx configuration, caching, rate limiting
- **Monitoring**: Health checks, logging, and optional Prometheus integration
- **Scalability**: Horizontal pod autoscaling and cluster autoscaling
- **Reliability**: Persistent storage, health probes, and graceful shutdowns

The deployment supports up to 40GB file uploads with proper chunking, parallel processing, and comprehensive error handling. All components are containerized and managed through Kubernetes for easy maintenance and scaling.
