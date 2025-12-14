# 🔧 Nginx Reverse Proxy Setup Guide

Complete step-by-step guide for setting up Nginx as a reverse proxy for Hypersend application on production servers.

## 📋 Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Basic Configuration](#basic-configuration)
- [SSL/TLS Setup](#ssltls-setup)
- [Advanced Configuration](#advanced-configuration)
- [Testing & Verification](#testing--verification)
- [Troubleshooting](#troubleshooting)
- [Production Best Practices](#production-best-practices)

---

## 🎯 Overview

### What is Nginx?
Nginx is a high-performance web server and reverse proxy that sits between clients and your backend services. For Hypersend, it provides:

- **Load Balancing**: Distribute traffic across multiple backend instances
- **SSL/TLS Termination**: Handle HTTPS encryption
- **Static File Serving**: Efficiently serve frontend assets
- **WebSocket Support**: Proxy WebSocket connections for real-time features
- **Security**: Additional security layer with rate limiting and headers
- **Caching**: Cache responses to improve performance

### Architecture
```
Client Request → Nginx (Port 80/443) → Backend API (Port 8000)
                     ↓
                Frontend Static Files
```

---

## 📦 Prerequisites

### System Requirements
- Ubuntu 20.04+ / Debian 10+ / CentOS 7+ / RHEL 7+
- Root or sudo access
- Domain name (optional but recommended for SSL)
- Ports 80 and 443 open in firewall

### Before You Start
Ensure your Hypersend application is running:
```bash
# Test backend is accessible
curl http://localhost:8000/health

# If using Docker
docker-compose ps
```

---

## 🚀 Installation

### Step 1: Install Nginx

#### Ubuntu/Debian
```bash
# Update package list
sudo apt update

# Install Nginx
sudo apt install -y nginx

# Verify installation
nginx -v
# Expected output: nginx version: nginx/1.18.0 (or higher)
```

#### CentOS/RHEL
```bash
# Install Nginx from EPEL repository
sudo yum install -y epel-release
sudo yum install -y nginx

# Start Nginx service
sudo systemctl start nginx

# Verify installation
nginx -v
```

#### Using Docker (Alternative)
```bash
# Already included in docker-compose.yml
# Just run:
docker-compose up -d nginx
```

### Step 2: Start and Enable Nginx

```bash
# Start Nginx
sudo systemctl start nginx

# Enable Nginx to start on boot
sudo systemctl enable nginx

# Check status
sudo systemctl status nginx
# Should show: Active: active (running)
```

### Step 3: Configure Firewall

#### UFW (Ubuntu)
```bash
# Allow HTTP and HTTPS
sudo ufw allow 'Nginx Full'

# Or allow specific ports
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Check firewall status
sudo ufw status
```

#### FirewallD (CentOS/RHEL)
```bash
# Allow HTTP and HTTPS
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https

# Reload firewall
sudo firewall-cmd --reload

# Verify rules
sudo firewall-cmd --list-all
```

---

## ⚙️ Basic Configuration

### Step 1: Create Configuration Directory Structure

```bash
# Create directories for organization
sudo mkdir -p /etc/nginx/sites-available
sudo mkdir -p /etc/nginx/sites-enabled
sudo mkdir -p /etc/nginx/ssl
sudo mkdir -p /var/log/nginx/hypersend
```

### Step 2: Backup Default Configuration

```bash
# Backup original nginx.conf
sudo cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup

# Backup default site config
sudo cp /etc/nginx/sites-available/default /etc/nginx/sites-available/default.backup
```

### Step 3: Create Hypersend Configuration

Create a new configuration file:
```bash
sudo nano /etc/nginx/sites-available/hypersend.conf
```

Paste the following configuration:

```nginx
# Hypersend Nginx Configuration
# HTTP Server Block (Port 80)

upstream hypersend_backend {
    # Backend API server
    server localhost:8000;
    
    # For multiple backend instances (load balancing)
    # server localhost:8001;
    # server localhost:8002;
    
    keepalive 64;
}

upstream hypersend_frontend {
    # Frontend server (if running separately)
    server localhost:3000;
    keepalive 32;
}

server {
    listen 80;
    listen [::]:80;
    
    # Replace with your domain or server IP
    server_name your_domain.com www.your_domain.com;
    # Or use IP: server_name 139.59.82.105;
    
    # Request limits
    client_max_body_size 100M;
    client_body_timeout 300s;
    
    # Logging
    access_log /var/log/nginx/hypersend/access.log;
    error_log /var/log/nginx/hypersend/error.log warn;
    
    # Root directory (for static files if needed)
    root /var/www/hypersend;
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_types text/plain text/css text/xml text/javascript 
               application/json application/javascript application/xml+rss;
    gzip_min_length 1000;
    
    # Backend API proxy
    location /api/ {
        proxy_pass http://hypersend_backend;
        
        # Proxy headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Buffering
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
        proxy_busy_buffers_size 8k;
    }
    
    # WebSocket support for real-time features
    location /ws/ {
        proxy_pass http://hypersend_backend;
        
        # WebSocket headers
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Disable buffering for WebSocket
        proxy_buffering off;
        
        # Timeouts for long-lived connections
        proxy_connect_timeout 7d;
        proxy_send_timeout 7d;
        proxy_read_timeout 7d;
    }
    
    # Health check endpoint
    location /health {
        proxy_pass http://hypersend_backend/health;
        proxy_set_header Host $host;
        access_log off;
    }
    
    # API documentation
    location /docs {
        proxy_pass http://hypersend_backend/docs;
        proxy_set_header Host $host;
    }
    
    location /redoc {
        proxy_pass http://hypersend_backend/redoc;
        proxy_set_header Host $host;
    }
    
    # Static files for frontend
    location / {
        # If frontend is served by a separate server
        proxy_pass http://hypersend_frontend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        
        # Or serve static files directly
        # try_files $uri $uri/ /index.html;
    }
    
    # Uploaded files location
    location /uploads/ {
        alias /var/www/hypersend/uploads/;
        expires 7d;
        add_header Cache-Control "public, immutable";
    }
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # Hide Nginx version
    server_tokens off;
}
```

### Step 4: Enable the Configuration

```bash
# Create symbolic link to enable site
sudo ln -s /etc/nginx/sites-available/hypersend.conf /etc/nginx/sites-enabled/

# Remove default site (optional)
sudo rm /etc/nginx/sites-enabled/default

# Test configuration for syntax errors
sudo nginx -t
# Expected output:
# nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
# nginx: configuration file /etc/nginx/nginx.conf test is successful
```

### Step 5: Update Main Nginx Configuration

Edit main configuration:
```bash
sudo nano /etc/nginx/nginx.conf
```

Ensure these settings are present:

```nginx
user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 2048;
    use epoll;
}

http {
    # Basic settings
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;
    
    # File types
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Logging
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    
    # Gzip compression
    gzip on;
    gzip_disable "msie6";
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml text/javascript
               application/json application/javascript application/xml+rss;
    
    # Include site configurations
    include /etc/nginx/sites-enabled/*;
}
```

### Step 6: Reload Nginx

```bash
# Reload Nginx to apply changes
sudo systemctl reload nginx

# Or restart if needed
sudo systemctl restart nginx

# Check status
sudo systemctl status nginx
```

---

## 🔒 SSL/TLS Setup

### Option 1: Let's Encrypt (Free SSL - Recommended)

#### Step 1: Install Certbot

```bash
# Ubuntu/Debian
sudo apt install -y certbot python3-certbot-nginx

# CentOS/RHEL
sudo yum install -y certbot python3-certbot-nginx
```

#### Step 2: Obtain SSL Certificate

```bash
# Stop Nginx temporarily
sudo systemctl stop nginx

# Obtain certificate
sudo certbot certonly --standalone -d your_domain.com -d www.your_domain.com

# Follow the prompts:
# - Enter your email address
# - Agree to terms of service
# - Choose whether to share email with EFF

# Certificates will be saved to:
# /etc/letsencrypt/live/your_domain.com/fullchain.pem
# /etc/letsencrypt/live/your_domain.com/privkey.pem
```

#### Step 3: Update Nginx Configuration for HTTPS

Edit your Hypersend configuration:
```bash
sudo nano /etc/nginx/sites-available/hypersend.conf
```

Add HTTPS server block:

```nginx
# HTTP to HTTPS redirect
server {
    listen 80;
    listen [::]:80;
    server_name your_domain.com www.your_domain.com;
    
    # Redirect all HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

# HTTPS Server Block
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name your_domain.com www.your_domain.com;
    
    # SSL certificates
    ssl_certificate /etc/letsencrypt/live/your_domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your_domain.com/privkey.pem;
    
    # SSL protocols and ciphers
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers on;
    
    # SSL session cache
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # OCSP stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate /etc/letsencrypt/live/your_domain.com/chain.pem;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # Request limits
    client_max_body_size 100M;
    
    # Logging
    access_log /var/log/nginx/hypersend/access.log;
    error_log /var/log/nginx/hypersend/error.log warn;
    
    # Backend API proxy
    location /api/ {
        proxy_pass http://hypersend_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Ssl on;
        
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    # WebSocket support
    location /ws/ {
        proxy_pass http://hypersend_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        
        proxy_buffering off;
        proxy_connect_timeout 7d;
        proxy_send_timeout 7d;
        proxy_read_timeout 7d;
    }
    
    # Health check
    location /health {
        proxy_pass http://hypersend_backend/health;
        proxy_set_header Host $host;
        access_log off;
    }
    
    # Frontend
    location / {
        proxy_pass http://hypersend_frontend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

#### Step 4: Test and Reload

```bash
# Test configuration
sudo nginx -t

# Reload Nginx
sudo systemctl reload nginx

# Start Nginx
sudo systemctl start nginx
```

#### Step 5: Set Up Auto-Renewal

```bash
# Certbot auto-renewal is already configured by default
# Test renewal process
sudo certbot renew --dry-run

# Check renewal timer
sudo systemctl status certbot.timer

# Certificates will auto-renew before expiration (every 60 days)
```

### Option 2: Self-Signed Certificate (Development/Testing Only)

```bash
# Create SSL directory
sudo mkdir -p /etc/nginx/ssl

# Generate self-signed certificate (valid for 365 days)
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/hypersend.key \
    -out /etc/nginx/ssl/hypersend.crt

# Follow prompts:
# Country Name: IN
# State: Your State
# Locality: Your City
# Organization Name: Your Company
# Common Name: your_domain.com (important!)

# Use in nginx.conf:
# ssl_certificate /etc/nginx/ssl/hypersend.crt;
# ssl_certificate_key /etc/nginx/ssl/hypersend.key;
```

---

## 🎨 Advanced Configuration

### Rate Limiting

Add to your configuration to prevent abuse:

```nginx
# Add to http block in /etc/nginx/nginx.conf
http {
    # Define rate limit zones
    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login_limit:10m rate=5r/m;
    
    # Continue with other settings...
}

# Add to server block in hypersend.conf
server {
    # Rate limit for API endpoints
    location /api/ {
        limit_req zone=api_limit burst=20 nodelay;
        proxy_pass http://hypersend_backend;
        # ... other settings
    }
    
    # Strict rate limit for login
    location /api/auth/login {
        limit_req zone=login_limit burst=3 nodelay;
        proxy_pass http://hypersend_backend;
        # ... other settings
    }
}
```

### Caching

Add caching for better performance:

```nginx
# Add to http block
http {
    # Cache configuration
    proxy_cache_path /var/cache/nginx/hypersend levels=1:2 
                     keys_zone=hypersend_cache:10m 
                     max_size=1g inactive=60m 
                     use_temp_path=off;
}

# Add to location blocks
location /api/public/ {
    proxy_cache hypersend_cache;
    proxy_cache_valid 200 60m;
    proxy_cache_valid 404 10m;
    proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;
    proxy_cache_background_update on;
    proxy_cache_lock on;
    
    add_header X-Cache-Status $upstream_cache_status;
    
    proxy_pass http://hypersend_backend;
}

# Static files caching
location ~* \.(jpg|jpeg|png|gif|ico|css|js|svg|woff|woff2|ttf|eot)$ {
    expires 7d;
    add_header Cache-Control "public, immutable";
    access_log off;
}
```

### Load Balancing

For multiple backend instances:

```nginx
upstream hypersend_backend {
    # Load balancing method (default is round-robin)
    least_conn;  # or: ip_hash; least_time;
    
    # Backend servers
    server localhost:8000 weight=3;
    server localhost:8001 weight=2;
    server localhost:8002 weight=1;
    
    # Health checks
    server localhost:8003 backup;  # Backup server
    
    # Connection settings
    keepalive 32;
    keepalive_timeout 60s;
}
```

### IP Whitelisting

Restrict access to admin endpoints:

```nginx
location /api/admin/ {
    # Allow specific IPs
    allow 192.168.1.0/24;
    allow 10.0.0.1;
    deny all;
    
    proxy_pass http://hypersend_backend;
}
```

### DDoS Protection

```nginx
# Add to http block
http {
    # Connection limits per IP
    limit_conn_zone $binary_remote_addr zone=conn_limit:10m;
    
    # Request rate limits
    limit_req_zone $binary_remote_addr zone=req_limit:10m rate=10r/s;
}

# Add to server block
server {
    # Limit connections per IP
    limit_conn conn_limit 10;
    
    # Limit request rate
    limit_req zone=req_limit burst=20 nodelay;
    
    # Set timeouts
    client_body_timeout 10s;
    client_header_timeout 10s;
    send_timeout 10s;
}
```

---

## ✅ Testing & Verification

### Step 1: Check Configuration Syntax

```bash
# Test Nginx configuration
sudo nginx -t

# Expected output:
# nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
# nginx: configuration file /etc/nginx/nginx.conf test is successful
```

### Step 2: Test HTTP Access

```bash
# Test health endpoint
curl http://your_domain.com/health
# Expected: {"status": "healthy"}

# Test API endpoint
curl http://your_domain.com/api/health

# Test with headers
curl -I http://your_domain.com
```

### Step 3: Test HTTPS Access

```bash
# Test HTTPS
curl -k https://your_domain.com/health

# Test SSL certificate
openssl s_client -connect your_domain.com:443 -servername your_domain.com

# Check SSL Labs rating (online)
# Visit: https://www.ssllabs.com/ssltest/analyze.html?d=your_domain.com
```

### Step 4: Test WebSocket Connection

```bash
# Install websocat for testing
curl -LO https://github.com/vi/websocat/releases/download/v1.11.0/websocat_amd64-linux
chmod +x websocat_amd64-linux
sudo mv websocat_amd64-linux /usr/local/bin/websocat

# Test WebSocket connection
websocat wss://your_domain.com/ws/test_user
```

### Step 5: Monitor Logs

```bash
# Watch access logs
sudo tail -f /var/log/nginx/hypersend/access.log

# Watch error logs
sudo tail -f /var/log/nginx/hypersend/error.log

# Watch all Nginx logs
sudo tail -f /var/log/nginx/*.log
```

### Step 6: Performance Testing

```bash
# Install Apache Bench
sudo apt install apache2-utils

# Test with 100 requests, 10 concurrent
ab -n 100 -c 10 http://your_domain.com/health

# Test with authentication
ab -n 100 -c 10 -H "Authorization: Bearer YOUR_TOKEN" \
   http://your_domain.com/api/users/profile
```

---

## 🐛 Troubleshooting

### Issue 1: "502 Bad Gateway" Error

**Cause:** Backend service is not running or not accessible

**Solution:**
```bash
# Check backend is running
curl http://localhost:8000/health

# Start backend if not running
cd /path/to/hypersend
docker-compose up -d backend

# Check backend logs
docker-compose logs backend

# Verify upstream configuration in Nginx
sudo nginx -T | grep upstream
```

### Issue 2: "413 Request Entity Too Large"

**Cause:** File upload size exceeds limit

**Solution:**
```bash
# Edit Nginx configuration
sudo nano /etc/nginx/sites-available/hypersend.conf

# Add or increase:
client_max_body_size 100M;

# Reload Nginx
sudo systemctl reload nginx
```

### Issue 3: "504 Gateway Timeout"

**Cause:** Backend taking too long to respond

**Solution:**
```nginx
# Increase timeouts in location block
location /api/ {
    proxy_connect_timeout 300;
    proxy_send_timeout 300;
    proxy_read_timeout 300;
    send_timeout 300;
    proxy_pass http://hypersend_backend;
}
```

### Issue 4: WebSocket Connection Fails

**Cause:** Missing WebSocket upgrade headers

**Solution:**
```nginx
location /ws/ {
    proxy_pass http://hypersend_backend;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    
    # Disable buffering
    proxy_buffering off;
    
    # Long timeouts for persistent connections
    proxy_connect_timeout 7d;
    proxy_send_timeout 7d;
    proxy_read_timeout 7d;
}
```

### Issue 5: SSL Certificate Not Working

**Solution:**
```bash
# Check certificate files exist
sudo ls -la /etc/letsencrypt/live/your_domain.com/

# Test certificate
sudo certbot certificates

# Renew if expired
sudo certbot renew

# Check Nginx SSL configuration
sudo nginx -T | grep ssl_certificate
```

### Issue 6: Nginx Won't Start

**Solution:**
```bash
# Check for errors
sudo nginx -t

# View error log
sudo tail -50 /var/log/nginx/error.log

# Check if port is already in use
sudo netstat -tlnp | grep :80
sudo netstat -tlnp | grep :443

# Check Nginx status
sudo systemctl status nginx -l
```

### Common Log Locations

```bash
# Nginx main logs
/var/log/nginx/access.log
/var/log/nginx/error.log

# Hypersend specific logs
/var/log/nginx/hypersend/access.log
/var/log/nginx/hypersend/error.log

# Nginx configuration test
sudo nginx -t

# Nginx full configuration dump
sudo nginx -T
```

---

## 🏆 Production Best Practices

### Security Hardening

1. **Hide Nginx Version**
   ```nginx
   server_tokens off;
   ```

2. **Disable Unused HTTP Methods**
   ```nginx
   if ($request_method !~ ^(GET|POST|PUT|DELETE|OPTIONS)$ ) {
       return 405;
   }
   ```

3. **Implement Rate Limiting**
   - Protect against brute force attacks
   - Limit login attempts
   - Throttle API requests

4. **Use Strong SSL Configuration**
   - TLS 1.2 and 1.3 only
   - Strong cipher suites
   - HSTS header

5. **Enable Security Headers**
   ```nginx
   add_header X-Frame-Options "SAMEORIGIN";
   add_header X-Content-Type-Options "nosniff";
   add_header X-XSS-Protection "1; mode=block";
   add_header Strict-Transport-Security "max-age=31536000";
   ```

### Performance Optimization

1. **Enable Gzip Compression**
   ```nginx
   gzip on;
   gzip_comp_level 6;
   gzip_types text/plain text/css application/json application/javascript;
   ```

2. **Configure Caching**
   - Cache static assets
   - Implement proxy caching for API responses
   - Set appropriate cache headers

3. **Optimize Worker Processes**
   ```nginx
   worker_processes auto;
   worker_connections 2048;
   ```

4. **Use HTTP/2**
   ```nginx
   listen 443 ssl http2;
   ```

### Monitoring & Logging

1. **Structured Logging**
   ```nginx
   log_format json_combined escape=json
   '{
       "time":"$time_iso8601",
       "remote_addr":"$remote_addr",
       "request":"$request",
       "status":$status,
       "body_bytes_sent":$body_bytes_sent,
       "request_time":$request_time
   }';
   
   access_log /var/log/nginx/access.json json_combined;
   ```

2. **Log Rotation**
   ```bash
   # Create logrotate config
   sudo nano /etc/logrotate.d/hypersend
   ```
   
   ```
   /var/log/nginx/hypersend/*.log {
       daily
       rotate 14
       compress
       delaycompress
       notifempty
       create 0640 www-data adm
       sharedscripts
       postrotate
           [ -f /var/run/nginx.pid ] && kill -USR1 `cat /var/run/nginx.pid`
       endscript
   }
   ```

3. **Set Up Monitoring**
   - Monitor Nginx status with stub_status
   - Use tools like Prometheus + Grafana
   - Set up alerts for error rates

### Backup & Recovery

```bash
# Backup Nginx configuration
sudo tar -czf nginx-config-backup-$(date +%Y%m%d).tar.gz /etc/nginx/

# Backup SSL certificates
sudo tar -czf ssl-backup-$(date +%Y%m%d).tar.gz /etc/letsencrypt/

# Test restore
sudo tar -xzf nginx-config-backup-20250101.tar.gz -C /tmp/
```

### Regular Maintenance

```bash
# Weekly tasks
- Check error logs for issues
- Review access patterns
- Update Nginx to latest stable version
- Test SSL certificate renewal

# Monthly tasks
- Review and update security headers
- Analyze performance metrics
- Update rate limiting rules if needed
- Backup configurations
```

---

## 📚 Additional Resources

### Documentation
- [Official Nginx Documentation](https://nginx.org/en/docs/)
- [Nginx Reverse Proxy Guide](https://docs.nginx.com/nginx/admin-guide/web-server/reverse-proxy/)
- [Let's Encrypt Documentation](https://letsencrypt.org/docs/)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)

### Tools
- [SSL Labs Server Test](https://www.ssllabs.com/ssltest/)
- [Security Headers Check](https://securityheaders.com/)
- [GTmetrix Performance Analysis](https://gtmetrix.com/)
- [WebPageTest](https://www.webpagetest.org/)

### Configuration Generators
- [Mozilla SSL Config Generator](https://ssl-config.mozilla.org/)
- [NGINXConfig](https://www.digitalocean.com/community/tools/nginx)

---

## 🎯 Quick Reference Commands

```bash
# Start/Stop/Restart Nginx
sudo systemctl start nginx
sudo systemctl stop nginx
sudo systemctl restart nginx
sudo systemctl reload nginx  # Reload config without downtime

# Test configuration
sudo nginx -t

# View configuration
sudo nginx -T

# Check status
sudo systemctl status nginx

# View logs
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log

# Enable/Disable site
sudo ln -s /etc/nginx/sites-available/site.conf /etc/nginx/sites-enabled/
sudo rm /etc/nginx/sites-enabled/site.conf

# SSL certificate renewal
sudo certbot renew
sudo certbot renew --dry-run
```

---

## 📞 Support

For issues specific to Hypersend:
- GitHub Issues: [github.com/Mayankvlog/Hypersend/issues](https://github.com/Mayankvlog/Hypersend/issues)
- Email: mayank.kr0311@gmail.com

For Nginx-related issues:
- Nginx Forum: [forum.nginx.org](https://forum.nginx.org/)
- Stack Overflow: [stackoverflow.com/questions/tagged/nginx](https://stackoverflow.com/questions/tagged/nginx)

---

**Last Updated:** December 14, 2025  
**Version:** 1.0.0  
**Maintained by:** Mayank Kumar (@Mayankvlog)
