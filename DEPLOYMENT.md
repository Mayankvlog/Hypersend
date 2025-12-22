# Zaply Deployment Guide

## SSL/TLS Certificate Setup with Let's Encrypt

### Prerequisites
- Domain registered and DNS pointing to your VPS IP
- VPS with Ubuntu/Debian
- `certbot` and `certbot-nginx` installed
- Docker and Docker Compose running

### Step 1: Stop Docker Containers (temporarily)
The nginx container binds to port 80. Stop it so certbot can validate the certificate:

```bash
docker compose down
```

### Step 2: Obtain SSL Certificate
Use certbot in standalone mode to obtain a certificate for your domain:

```bash
sudo certbot certonly --standalone \
  -d zaply.in.net \
  -d www.zaply.in.net \
  --agree-tos \
  --email your-email@example.com
```

This will place certificates at:
- Certificate: `/etc/letsencrypt/live/zaply.in.net/fullchain.pem`
- Key: `/etc/letsencrypt/live/zaply.in.net/privkey.pem`

### Step 3: Set Certificate Permissions
Ensure nginx in the Docker container can read the certificates:

```bash
sudo chmod 644 /etc/letsencrypt/live/zaply.in.net/fullchain.pem
sudo chmod 644 /etc/letsencrypt/live/zaply.in.net/privkey.pem
sudo chmod 755 /etc/letsencrypt/live/zaply.in.net
sudo chmod 755 /etc/letsencrypt/live
```

### Step 4: Mount Certificates in Docker
The `docker-compose.yml` already mounts the letsencrypt directory:

```yaml
volumes:
  - /etc/letsencrypt:/etc/letsencrypt:ro
```

Verify this is present in your `docker-compose.yml`.

### Step 5: Start Docker Containers
Restart the containers with SSL enabled:

```bash
docker compose up -d --build
```

### Step 6: Auto-Renew Certificates
Set up a cron job to auto-renew certificates before they expire:

```bash
sudo crontab -e
```

Add this line (checks daily, renews 30 days before expiry):

```cron
0 2 * * * sudo certbot renew --quiet && docker compose -f /hypersend/Hypersend/docker-compose.yml restart nginx
```

Replace `/hypersend/Hypersend/` with your actual repository path.

### Verification

Check if HTTPS is working:

```bash
curl -I https://zaply.in.net
```

Check certificate details:

```bash
sudo certbot certificates
```

### Troubleshooting

**Port 80 already in use:**
- Ensure Docker containers are stopped: `docker compose down`
- Check for running processes: `sudo lsof -i :80`

**Certificate path issues:**
- Verify paths exist: `ls -la /etc/letsencrypt/live/zaply.in.net/`
- Check permissions: `ls -l /etc/letsencrypt/`

**Nginx fails to start:**
- Check Docker logs: `docker compose logs nginx`
- Verify mount path in docker-compose.yml

## Frontend & Backend Deployment

### Build Frontend
Flutter web build happens in Docker during `docker compose up -d --build`. No manual steps required.

### Backend API
FastAPI backend is automatically deployed as part of Docker Compose. Accessible at:
- HTTP: `http://zaply.in.net/api/v1/`
- HTTPS: `https://zaply.in.net/api/v1/`

### Database
MongoDB is managed by Docker Compose. Data is persisted in the `data/` directory.

## Health Checks

All services expose `/health` endpoint:

```bash
curl https://zaply.in.net/health
```

## Environment Variables

Set in `.env` file:
- `MONGODB_URL`: MongoDB connection string
- `JWT_SECRET`: JWT signing secret
- `API_BASE_URL`: (Frontend only) API base URL for web build

See `.env.example` for all available variables.
