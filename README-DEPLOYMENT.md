# Hypersend VPS Deployment Guide

This guide will help you deploy Hypersend on your VPS using Docker Hub images.

## Prerequisites

### System Requirements
- **OS**: Ubuntu 20.04+ or CentOS 8+
- **RAM**: Minimum 4GB (Recommended 8GB+)
- **Storage**: Minimum 20GB (Recommended 50GB+)
- **CPU**: Minimum 2 cores (Recommended 4+ cores)

### Software Requirements
- Docker 20.10+
- Docker Compose 2.0+
- Git
- OpenSSL (for SSL certificates)

## Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/mayankvlog/hypersend.git
cd hypersend
```

### 2. Configure Environment Variables
```bash
# Copy the production environment template
cp .env.production .env

# Edit the environment file with your actual values
nano .env
```

**Important**: Update these values in `.env`:
- `SECRET_KEY` - Generate a new secure secret
- `MONGODB_URI` - Your MongoDB connection string
- `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` - Your AWS credentials
- `SMTP_PASSWORD` - Your email service password
- `TURN_USERNAME` and `TURN_PASSWORD` - TURN server credentials
- All E2EE keys - Generate new secure keys

### 3. Make Deployment Script Executable
```bash
chmod +x deploy-vps.sh
```

### 4. Deploy
```bash
./deploy-vps.sh deploy
```

## Detailed Configuration

### Environment Variables

#### Core Configuration
```bash
SECRET_KEY=your_super_secret_key_here
DOMAIN_NAME=your-domain.com
API_BASE_URL=https://your-domain.com/api/v1
```

#### Database Configuration
```bash
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/hypersend
MONGODB_ATLAS_ENABLED=true
```

#### AWS S3 Configuration
```bash
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
AWS_REGION=us-east-1
S3_BUCKET=your-s3-bucket-name
```

#### Email Configuration
```bash
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-gmail-app-password
EMAIL_FROM=noreply@your-domain.com
```

#### TURN Server Configuration
```bash
TURN_USERNAME=turnuser
TURN_PASSWORD=secure_turn_password
```

### SSL Certificates

#### Option 1: Let's Encrypt (Recommended)
```bash
# Install certbot
sudo apt update
sudo apt install certbot

# Generate certificates
sudo certbot certonly --standalone -d your-domain.com

# Copy certificates to project directory
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem ./ssl/cert.pem
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem ./ssl/key.pem
```

#### Option 2: Self-Signed (For Testing)
The deployment script will automatically generate self-signed certificates if none exist.

## Deployment Commands

### Deploy Application
```bash
./deploy-vps.sh deploy
```

### Check Status
```bash
./deploy-vps.sh status
```

### View Logs
```bash
# View all logs
./deploy-vps.sh logs

# View specific service logs
./deploy-vps.sh logs backend
./deploy-vps.sh logs frontend
./deploy-vps.sh logs redis
```

### Create Backup
```bash
./deploy-vps.sh backup
```

### Rollback to Previous Version
```bash
# List available backups
ls -la /opt/backups/hypersend/

# Rollback to specific backup
./deploy-vps.sh rollback hypersend-20231215-143022
```

## Service URLs

After deployment, your services will be available at:

- **Frontend**: `https://your-domain.com`
- **Backend API**: `https://your-domain.com/api/v1`
- **Health Check**: `https://your-domain.com/health`
- **WebSocket**: `wss://your-domain.com/api/v1/ws`

## Docker Hub Images

The deployment uses the following Docker Hub images:

- `mayankvlog/hypersend-backend:latest` - Backend API service
- `mayankvlog/hypersend-frontend:latest` - Frontend web application
- `nginx:1.25-alpine` - Reverse proxy and load balancer
- `redis:7.2-alpine` - In-memory cache and session storage
- `coturn/coturn:latest` - TURN server for voice/video calls

## Monitoring (Optional)

To enable monitoring services:

```bash
# Deploy with monitoring
docker-compose --profile monitoring up -d

# Access Grafana
# URL: http://your-domain.com:3001
# Username: admin
# Password: Set in GRAFANA_PASSWORD environment variable

# Access Prometheus
# URL: http://your-domain.com:9090
```

## Security Considerations

### 1. Firewall Configuration
```bash
# Allow HTTP/HTTPS
sudo ufw allow 80
sudo ufw allow 443

# Allow TURN server ports
sudo ufw allow 3478/udp
sudo ufw allow 3478/tcp
sudo ufw allow 5349/tcp

# Enable firewall
sudo ufw enable
```

### 2. SSL/TLS
- Always use HTTPS in production
- Keep SSL certificates updated
- Use strong cipher suites

### 3. Environment Variables
- Never commit `.env` files to version control
- Use strong, unique secrets
- Rotate keys regularly

### 4. Database Security
- Use MongoDB Atlas with IP whitelisting
- Enable authentication
- Use connection strings with TLS

## Troubleshooting

### Common Issues

#### 1. Services Not Starting
```bash
# Check logs
docker-compose logs

# Check resource usage
docker stats

# Check disk space
df -h
```

#### 2. SSL Certificate Issues
```bash
# Check certificate validity
openssl x509 -in ./ssl/cert.pem -text -noout

# Test SSL configuration
openssl s_client -connect your-domain.com:443
```

#### 3. Database Connection Issues
```bash
# Test MongoDB connection
docker-compose exec backend python -c "
from motor.motor_asyncio import AsyncIOMotorClient
import asyncio
async def test():
    client = AsyncIOMotorClient('mongodb://...')
    try:
        await client.admin.command('ping')
        print('MongoDB connection successful')
    except Exception as e:
        print(f'MongoDB connection failed: {e}')
    finally:
        client.close()
asyncio.run(test())
"
```

#### 4. Redis Connection Issues
```bash
# Test Redis connection
docker-compose exec redis redis-cli ping
```

### Performance Optimization

#### 1. Resource Limits
Adjust resource limits in `docker-compose.yml` based on your VPS specifications.

#### 2. Caching
- Redis is configured for optimal performance
- Nginx caching is enabled for static content

#### 3. Database Optimization
- Use MongoDB Atlas for better performance
- Enable connection pooling
- Monitor query performance

## Maintenance

### Regular Tasks

1. **Update Images**
```bash
docker-compose pull
docker-compose up -d
```

2. **Clean Up**
```bash
docker system prune -f
docker volume prune -f
```

3. **Backup**
```bash
./deploy-vps.sh backup
```

4. **Monitor Logs**
```bash
./deploy-vps.sh logs
```

### Scaling

#### Horizontal Scaling
To scale services, update the `deploy` section in `docker-compose.yml`:

```yaml
backend:
  deploy:
    replicas: 3  # Increase from 1 to 3
```

#### Vertical Scaling
Increase resource limits:

```yaml
backend:
  deploy:
    resources:
      limits:
        memory: 2G
        cpus: '1.0'
```

## Support

For issues and support:

1. Check the logs: `./deploy-vps.sh logs`
2. Review this documentation
3. Check the GitHub repository for known issues
4. Create an issue with detailed logs and configuration

## License

This deployment configuration is part of the Hypersend project. See the main project LICENSE file for details.
