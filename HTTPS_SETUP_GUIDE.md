# 🔒 HTTPS Setup Guide - VPS without Domain

Complete guide to enable HTTPS on your VPS (139.59.82.105) using self-signed certificates.

---

## ⚠️ Important Notice

**Self-signed certificates will show a browser warning** because they are not verified by a trusted Certificate Authority (CA). Users will see:
- ⚠️ "Your connection is not private"
- ⚠️ "NET::ERR_CERT_AUTHORITY_INVALID"

**This is normal for self-signed certificates.** Users need to click "Advanced" → "Proceed to site" to access.

---

## 🚀 Quick Setup (Already Done!)

All configuration files have been updated. Just deploy:

### Step 1: Commit and Push Changes

```powershell
cd c:\Users\mayan\Downloads\Addidas\hypersend
git add docker-compose.yml nginx.conf HTTPS_SETUP_GUIDE.md
git commit -m "Enable HTTPS with self-signed certificate"
git push origin main
```

### Step 2: Deploy on VPS

```bash
# SSH to VPS
ssh root@139.59.82.105

# Navigate to project
cd /hypersend/Hypersend

# Pull latest changes
git pull origin main

# Stop existing services
docker compose down

# Start with HTTPS enabled
docker compose up -d --build

# Wait for services to start
sleep 30

# Check status
docker compose ps
```

---

## 🌐 Access Your Application

### Frontend (Netlify)
- **HTTP**: Redirects to HTTPS automatically
- **HTTPS**: https://your-site.netlify.app ✅

### Backend (VPS)
- **HTTP**: http://139.59.82.105:8080 → Redirects to HTTPS
- **HTTPS**: https://139.59.82.105:8443 ✅ (Self-signed certificate warning)

### API Endpoints
- **HTTPS API**: https://139.59.82.105:8443/api/...
- **HTTPS Docs**: https://139.59.82.105:8443/docs

---

## 🔧 What Changed?

### 1. docker-compose.yml
- ✅ Added SSL certificate volume
- ✅ Auto-generates self-signed certificate on first run
- ✅ Certificate valid for 365 days
- ✅ Added HTTPS port (8443)

### 2. nginx.conf
- ✅ HTTP (port 80) redirects to HTTPS
- ✅ HTTPS (port 443) with SSL configuration
- ✅ Security headers added
- ✅ TLS 1.2 and 1.3 enabled

---

## 📱 How to Access (Browser Warning)

### Step 1: Open HTTPS URL
```
https://139.59.82.105:8443
```

### Step 2: Browser Warning Appears
You'll see: **"Your connection is not private"**

### Step 3: Proceed Anyway
1. Click **"Advanced"**
2. Click **"Proceed to 139.59.82.105 (unsafe)"**
3. ✅ You're in!

### Step 4: Accept Certificate (One-time)
Some browsers let you permanently accept the certificate.

---

## 🔐 Certificate Details

**Type**: Self-signed X.509 certificate
**Algorithm**: RSA 2048-bit
**Validity**: 365 days
**Subject**: CN=139.59.82.105
**Location**: `/etc/nginx/ssl/` inside nginx container

---

## 🆙 Upgrade to Trusted Certificate (Optional)

To remove browser warnings, you need a domain name:

### Option 1: Free Domain + Let's Encrypt
1. Get free domain from:
   - Freenom (free .tk, .ml, .ga domains)
   - DuckDNS (free subdomain)
   - No-IP (free subdomain)

2. Point domain to your VPS IP (139.59.82.105)

3. Use Let's Encrypt for free SSL:
   ```bash
   # Install certbot
   apt-get install certbot python3-certbot-nginx
   
   # Get certificate
   certbot --nginx -d yourdomain.com
   ```

### Option 2: Buy Domain
1. Buy domain from Namecheap, GoDaddy, etc. (~$10/year)
2. Point to your VPS
3. Use Let's Encrypt (free SSL)

---

## 🔄 Update Frontend to Use HTTPS Backend

### Update Netlify Environment Variables

1. Go to Netlify dashboard
2. **Site settings** → **Environment variables**
3. Update:
   ```
   API_BASE_URL = https://139.59.82.105:8443
   PRODUCTION_API_URL = https://139.59.82.105:8443
   ```

4. **Deploys** → **Trigger deploy** → **Deploy site**

---

## ✅ Verify HTTPS is Working

### Test Backend HTTPS
```bash
# From VPS
curl -k https://localhost:443/health

# From outside
curl -k https://139.59.82.105:8443/health
```

### Test Redirect
```bash
# HTTP should redirect to HTTPS
curl -I http://139.59.82.105:8080
# Should show: Location: https://...
```

### Check Logs
```bash
docker compose logs nginx
docker compose logs backend
```

---

## 🐛 Troubleshooting

### Certificate Not Generated

**Problem**: SSL certificate files not found

**Solution**:
```bash
# Recreate nginx container
docker compose down
docker volume rm hypersend_nginx_ssl
docker compose up -d nginx

# Check logs
docker compose logs nginx
```

### Port 443 Already in Use

**Problem**: Another service using port 443

**Solution**:
```bash
# Find what's using port 443
sudo lsof -i :443

# Stop conflicting service
sudo systemctl stop <service-name>

# Restart nginx
docker compose restart nginx
```

### Browser Still Shows HTTP

**Problem**: Browser cached old HTTP version

**Solution**:
1. Clear browser cache (Ctrl+Shift+Delete)
2. Use incognito/private mode
3. Force HTTPS: type `https://` manually

---

## 📊 Security Comparison

| Feature | HTTP | HTTPS (Self-signed) | HTTPS (Trusted CA) |
|---------|------|---------------------|-------------------|
| Encryption | ❌ No | ✅ Yes | ✅ Yes |
| Browser Warning | ❌ No | ⚠️ Yes | ✅ No |
| SEO Ranking | ❌ Low | ⚠️ Medium | ✅ High |
| User Trust | ❌ Low | ⚠️ Medium | ✅ High |
| Cost | Free | Free | Free (with domain) |
| Setup Time | 5 min | 10 min | 30 min |

---

## 💡 Recommendations

### For Development/Testing
✅ **Self-signed certificate is fine**
- Quick setup
- Free
- Encryption works

### For Production
⚠️ **Get a domain + Let's Encrypt**
- No browser warnings
- Better SEO
- User trust
- Professional appearance

---

## 📞 Support

- **Issues**: GitHub Issues
- **Email**: support@zaply.dev
- **Docs**: https://docs.zaply.dev

---

**Last Updated**: December 12, 2025

Made with 🔒 by Mayan