# ⚡ Nginx Reverse Proxy - Quick Start Guide

Fast and simple steps to set up Nginx as a reverse proxy for Hypersend in production.

## 📋 5-Minute Quick Setup

### Prerequisites
- Ubuntu/Debian/CentOS server with root/sudo access
- Hypersend backend running on port 8000
- Ports 80 and 443 open in firewall

### Step 1: Install Nginx (2 minutes)

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install -y nginx
sudo systemctl start nginx
sudo systemctl enable nginx
```

#### CentOS/RHEL
```bash
sudo yum install -y epel-release nginx
sudo systemctl start nginx
sudo systemctl enable nginx
```

### Step 2: Create Configuration (1 minute)

```bash
sudo nano /etc/nginx/sites-available/hypersend.conf
```

Paste this configuration:

```nginx
upstream hypersend_backend {
    server localhost:8000;
    keepalive 64;
}

server {
    listen 80;
    listen [::]:80;
    server_name your_domain.com www.your_domain.com;
    
    client_max_body_size 100M;
    
    location /api/ {
        proxy_pass http://hypersend_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    location /ws/ {
        proxy_pass http://hypersend_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_buffering off;
        proxy_connect_timeout 7d;
        proxy_send_timeout 7d;
        proxy_read_timeout 7d;
    }
    
    location / {
        proxy_pass http://hypersend_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

**Replace `your_domain.com` with your actual domain or server IP**

### Step 3: Enable Configuration (30 seconds)

```bash
sudo ln -s /etc/nginx/sites-available/hypersend.conf /etc/nginx/sites-enabled/
sudo rm /etc/nginx/sites-enabled/default  # Optional
sudo nginx -t  # Test configuration
sudo systemctl reload nginx
```

### Step 4: Test Access (1 minute)

```bash
# Test HTTP access
curl http://your_domain.com/health

# Test API endpoint
curl http://your_domain.com/api/health

# View logs if issues
sudo tail -f /var/log/nginx/error.log
```

✅ **Done!** Nginx is now proxying requests to your backend.

---

## 🔒 Add HTTPS with Let's Encrypt (5 minutes)

### Step 1: Install Certbot

```bash
sudo apt install -y certbot python3-certbot-nginx  # Ubuntu/Debian
# OR
sudo yum install -y certbot python3-certbot-nginx  # CentOS/RHEL
```

### Step 2: Obtain Certificate

```bash
sudo certbot certonly --standalone -d your_domain.com -d www.your_domain.com
```

Follow the prompts. Certificates will be saved to:
```
/etc/letsencrypt/live/your_domain.com/
```

### Step 3: Update Nginx Configuration

```bash
sudo nano /etc/nginx/sites-available/hypersend.conf
```

Replace the entire file with this HTTPS configuration:

```nginx
upstream hypersend_backend {
    server localhost:8000;
    keepalive 64;
}

# HTTP to HTTPS redirect
server {
    listen 80;
    listen [::]:80;
    server_name your_domain.com www.your_domain.com;
    return 301 https://$server_name$request_uri;
}

# HTTPS Server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name your_domain.com www.your_domain.com;
    
    ssl_certificate /etc/letsencrypt/live/your_domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your_domain.com/privkey.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    client_max_body_size 100M;
    
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    
    location /api/ {
        proxy_pass http://hypersend_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Ssl on;
    }
    
    location /ws/ {
        proxy_pass http://hypersend_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_buffering off;
        proxy_connect_timeout 7d;
        proxy_send_timeout 7d;
        proxy_read_timeout 7d;
    }
    
    location / {
        proxy_pass http://hypersend_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

### Step 4: Reload Nginx

```bash
sudo nginx -t
sudo systemctl reload nginx
```

### Step 5: Verify HTTPS

```bash
# Test HTTPS access
curl -k https://your_domain.com/health

# Check SSL certificate
openssl s_client -connect your_domain.com:443
```

### Step 6: Auto-Renewal (Optional but Recommended)

```bash
# Test renewal process
sudo certbot renew --dry-run

# Certificate auto-renews automatically (check systemctl timer)
sudo systemctl status certbot.timer
```

✅ **HTTPS is now enabled!** All traffic is encrypted and redirects from HTTP.

---

## 🔧 Common Configurations

### Rate Limiting (Prevent Abuse)

Add this to `/etc/nginx/nginx.conf` in the `http` block:

```nginx
http {
    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login_limit:10m rate=5r/m;
}
```

Add this to your server block in `hypersend.conf`:

```nginx
location /api/ {
    limit_req zone=api_limit burst=20 nodelay;
    proxy_pass http://hypersend_backend;
    # ... other settings
}

location /api/auth/login {
    limit_req zone=login_limit burst=3 nodelay;
    proxy_pass http://hypersend_backend;
    # ... other settings
}
```

### Gzip Compression (Faster Load Times)

Add to `/etc/nginx/nginx.conf` in the `http` block:

```nginx
gzip on;
gzip_vary on;
gzip_comp_level 6;
gzip_types text/plain text/css text/xml text/javascript
           application/json application/javascript application/xml+rss;
gzip_min_length 1000;
```

### File Upload Size Limit

Add to server block:

```nginx
client_max_body_size 500M;  # Increase to 500MB
```

### Load Balancing (Multiple Backends)

Update upstream block:

```nginx
upstream hypersend_backend {
    least_conn;  # Load balancing method
    
    server localhost:8000 weight=3;
    server localhost:8001 weight=2;
    server localhost:8002 weight=1;
    server localhost:8003 backup;  # Backup server
    
    keepalive 64;
}
```

---

## 🐛 Troubleshooting

### "502 Bad Gateway" Error

```bash
# Check if backend is running
curl http://localhost:8000/health

# Check Nginx error log
sudo tail -f /var/log/nginx/error.log

# Check upstream configuration
sudo nginx -T | grep upstream
```

### "Connection Refused"

```bash
# Verify backend is listening on port 8000
sudo netstat -tlnp | grep 8000

# Or using ss
sudo ss -tlnp | grep 8000
```

### Test Configuration Without Reload

```bash
# Test syntax without reloading
sudo nginx -t

# View full configuration
sudo nginx -T
```

### View Nginx Logs

```bash
# Access logs
sudo tail -f /var/log/nginx/access.log

# Error logs
sudo tail -f /var/log/nginx/error.log

# Filter for specific domain
sudo tail -f /var/log/nginx/access.log | grep your_domain.com

# Filter for errors only
sudo grep error /var/log/nginx/error.log
```

### Port Already in Use

```bash
# Check what's using port 80 or 443
sudo netstat -tlnp | grep :80
sudo netstat -tlnp | grep :443

# Kill process if needed (replace PID)
sudo kill -9 <PID>
```

---

## 📊 Performance Testing

### Install Apache Bench

```bash
sudo apt install apache2-utils
```

### Run Load Test

```bash
# 100 requests, 10 concurrent
ab -n 100 -c 10 http://your_domain.com/health

# With authentication
ab -n 100 -c 10 -H "Authorization: Bearer YOUR_TOKEN" \
   http://your_domain.com/api/users/profile
```

---

## 🔐 Security Headers

Add these to your server block for enhanced security:

```nginx
server {
    # ... existing config
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Hide Nginx version
    server_tokens off;
}
```

---

## 🚀 Useful Commands

```bash
# Reload Nginx (graceful, no downtime)
sudo systemctl reload nginx

# Restart Nginx
sudo systemctl restart nginx

# Stop Nginx
sudo systemctl stop nginx

# Start Nginx
sudo systemctl start nginx

# Check Nginx status
sudo systemctl status nginx

# Enable Nginx on boot
sudo systemctl enable nginx

# Disable Nginx from boot
sudo systemctl disable nginx

# Test configuration
sudo nginx -t

# Display full configuration
sudo nginx -T

# List loaded modules
nginx -V
```

---

## 📚 Detailed Documentation

For comprehensive setup including:
- Advanced configurations
- Complete SSL/TLS setup
- Caching and optimization
- Rate limiting and DDoS protection
- Detailed troubleshooting

👉 See the **[Complete Nginx Setup Guide](docs/NGINX_SETUP.md)**

---

## 🎯 Next Steps

1. ✅ Install Nginx
2. ✅ Create basic configuration
3. ✅ Enable HTTPS with Let's Encrypt
4. ✅ Test and verify
5. ⏳ (Optional) Add rate limiting, caching, load balancing
6. ⏳ (Optional) Set up monitoring and logging

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/Mayankvlog/Hypersend/issues)
- **Full Guide**: [docs/NGINX_SETUP.md](docs/NGINX_SETUP.md)
- **Email**: mayank.kr0311@gmail.com

---

**Last Updated**: December 14, 2025  
**For**: Hypersend v1.0.0  
**Author**: Mayank Kumar (@Mayankvlog)
