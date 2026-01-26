# Hypersend Kubernetes Deployment Guide for GCP

## Kubernetes YAML File Analysis

### Lines 1-8: Namespace
Creates `hypersend` namespace for resource isolation.

### Lines 11-69: ConfigMap
Stores non-sensitive configuration:
- API settings (JWT, tokens, file sizes)
- CORS origins
- Rate limiting (100 req/min)
- Email/SMTP settings
- Nginx configuration

### Lines 72-85: Secrets
Base64-encoded sensitive data:
- MongoDB: `hypersend` / `hypersend_secure_password`
- SMTP: `dummy_app_password_configure_in_env`

### Lines 88-415: Nginx ConfigMap
Complete nginx reverse proxy config with:
- SSL/TLS termination
- Rate limiting zones
- Security headers
- Upstream servers (backend:8000, frontend:80)
- HTTP→HTTPS redirects

### Lines 418-514: Persistent Volume Claims (7 total, 44Gi)
- mongodb-data: 10Gi
- mongodb-config: 1Gi  
- data: 20Gi
- uploads: 10Gi
- letsencrypt certs/lib: 2Gi
- nginx-cache: 2Gi

### Lines 517-616: MongoDB Deployment
- mongo:7.0 image
- 1 replica, 512Mi-1Gi memory
- Authentication enabled
- Health probes via mongosh

### Lines 619-720: Backend Deployment  
- hypersend/backend:latest image
- 2 replicas, 512Mi-1Gi memory
- Port 8000, health checks
- Mounts data/uploads volumes

### Lines 723-792: Frontend Deployment
- hypersend/frontend:latest image
- 2 replicas, 128Mi-256Mi memory
- Port 80, health checks

### Lines 795-910: Nginx Deployment
- nginx:alpine image
- 2 replicas, 128Mi-256Mi memory
- LoadBalancer service (ports 80/443)
- Auto-generates self-signed certs

### Lines 913-969: Ingress (Optional)
- External access via nginx ingress
- SSL termination
- Routes: /api→backend, /→frontend

---

## Prerequisites

### GCP Account Setup
1. Create GCP account with billing enabled
2. Install Google Cloud SDK
3. Install kubectl
4. Install Docker

### Authentication
```bash
gcloud auth login
gcloud config set project YOUR_PROJECT_ID
gcloud services enable container.googleapis.com
```

---

## GCP Setup

### 1. Create GKE Cluster
```bash
gcloud container clusters create hypersend-cluster \
  --zone=us-central1-a \
  --num-nodes=3 \
  --machine-type=e2-standard-2 \
  --disk-size=100GB \
  --enable-autoscaling \
  --min-nodes=2 \
  --max-nodes=5
```

### 2. Configure kubectl
```bash
gcloud container clusters get-credentials hypersend-cluster --zone=us-central1-a
kubectl cluster-info
```

---

## Build and Push Docker Images

### 1. Backend Dockerfile (if not exists)
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### 2. Frontend Dockerfile (if not exists)
```dockerfile
FROM nginx:alpine
COPY build/ /usr/share/nginx/html/
COPY nginx.conf /etc/nginx/nginx.conf
EXPOSE 80
```

### 3. Build and Push Images
```bash
# Enable Artifact Registry API
gcloud services enable artifactregistry.googleapis.com

# Create repository
gcloud artifacts repositories create hypersend-repo \
  --repository-format=docker \
  --location=us-central1

# Configure Docker auth
gcloud auth configure-docker us-central1-docker.pkg.dev

# Build and push backend
docker build -t us-central1-docker.pkg.dev/YOUR_PROJECT_ID/hypersend-repo/backend:latest ./backend
docker push us-central1-docker.pkg.dev/YOUR_PROJECT_ID/hypersend-repo/backend:latest

# Build and push frontend  
docker build -t us-central1-docker.pkg.dev/YOUR_PROJECT_ID/hypersend-repo/frontend:latest ./frontend
docker push us-central1-docker.pkg.dev/YOUR_PROJECT_ID/hypersend-repo/frontend:latest

# Update kubernetes.yaml with your image paths
sed -i 's|hypersend/backend:latest|us-central1-docker.pkg.dev/YOUR_PROJECT_ID/hypersend-repo/backend:latest|g' kubernetes.yaml
sed -i 's|hypersend/frontend:latest|us-central1-docker.pkg.dev/YOUR_PROJECT_ID/hypersend-repo/frontend:latest|g' kubernetes.yaml
```

---

## Deploy to Kubernetes

### 1. Deploy Infrastructure
```bash
# Deploy namespace and config
kubectl apply -f kubernetes.yaml --namespace=hypersend
```

### 2. Verify Deployment
```bash
# Check all resources
kubectl get all -n hypersend

# Check pods status
kubectl get pods -n hypersend -w

# Check services
kubectl get services -n hypersend

# Check PVCs
kubectl get pvc -n hypersend
```

### 3. Get External IP
```bash
# Get LoadBalancer external IP
kubectl get service nginx -n hypersend
# Wait for EXTERNAL-IP to be assigned
```

---

## Post-Deployment Configuration

### 1. Update DNS
Point your domain (zaply.in.net) to the LoadBalancer external IP:
```bash
kubectl get service nginx -n hypersend -o jsonpath='{.status.loadBalancer.ingress[0].ip}'
```

### 2. SSL Certificate Setup
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
```

### 3. Configure Production Secrets
```bash
# Update SMTP password
kubectl patch secret hypersend-secrets -n hypersend -p='{"data":{"SMTP_PASSWORD":"'$(echo -n 'your_real_smtp_password' | base64)'"}}'

# Update MongoDB password (optional)
kubectl patch secret hypersend-secrets -n hypersend -p='{"data":{"MONGO_PASSWORD":"'$(echo -n 'your_secure_mongo_password' | base64)'"}}'
```

---

## Monitoring and Troubleshooting

### 1. Check Logs
```bash
# Backend logs
kubectl logs -f deployment/backend -n hypersend

# Frontend logs
kubectl logs -f deployment/frontend -n hypersend

# Nginx logs
kubectl logs -f deployment/nginx -n hypersend

# MongoDB logs
kubectl logs -f deployment/mongodb -n hypersend
```

### 2. Debug Commands
```bash
# Port forward to local
kubectl port-forward service/backend 8000:8000 -n hypersend
kubectl port-forward service/frontend 3000:80 -n hypersend

# Exec into pod
kubectl exec -it deployment/backend -n hypersend -- /bin/bash

# Describe resources
kubectl describe pod <pod-name> -n hypersend
kubectl describe service nginx -n hypersend
```

### 3. Health Checks
```bash
# Test health endpoints
curl http://EXTERNAL_IP/health
curl http://EXTERNAL_IP/api/health
```

### 4. Scale Applications
```bash
# Scale backend
kubectl scale deployment backend --replicas=3 -n hypersend

# Scale frontend
kubectl scale deployment frontend --replicas=3 -n hypersend
```

---

## Production Checklist

- [ ] Update SECRET_KEY in ConfigMap
- [ ] Configure real SMTP password
- [ ] Set up proper domain DNS
- [ ] Configure SSL certificates
- [ ] Set up monitoring and alerting
- [ ] Configure backup strategy for MongoDB
- [ ] Set up log aggregation
- [ ] Review security settings
- [ ] Test disaster recovery
- [ ] Configure CI/CD pipeline

---

## Cleanup

To remove all resources:
```bash
kubectl delete namespace hypersend
gcloud container clusters delete hypersend-cluster --zone=us-central1-a
```
