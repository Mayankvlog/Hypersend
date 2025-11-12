# 🎯 HyperSend Deployment - Quick Reference Card

## 📋 One-Page Deployment Summary

---

## 🚀 DEPLOYMENT IN 5 STEPS

### Step 1: Create Accounts (30 min)
```
MongoDB Atlas:  https://www.mongodb.com/cloud/atlas
DockerHub:      https://hub.docker.com
DigitalOcean:   https://www.digitalocean.com
GitHub:         https://github.com
```

### Step 2: Create VPS (10 min)
```
DigitalOcean → Create Droplet
- Image: Ubuntu 22.04 LTS
- Plan: 2 vCPU, 4GB RAM, 80GB SSD ($24/month)
- Region: BLR1 (Bangalore)
- Copy IP address
```

### Step 3: Setup VPS (20 min)
```bash
ssh root@YOUR_VPS_IP
curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/hypersend/main/QUICK_SETUP.sh | bash
nano /root/Hypersend/.env  # Configure
cd /root/Hypersend && git clone https://github.com/YOUR_USERNAME/hypersend.git .
```

### Step 4: Add GitHub Secrets (10 min)
```
GitHub → Settings → Secrets → Add 6 secrets:
1. DOCKERHUB_USERNAME
2. DOCKERHUB_TOKEN
3. VPS_HOST (your IP)
4. VPS_USER (root)
5. VPS_PASSWORD
6. MONGODB_URI
```

### Step 5: Deploy (5 min)
```bash
git add . && git commit -m "Deploy" && git push origin main
# Watch GitHub Actions → Actions tab
```

---

## 🔗 IMPORTANT LINKS

| Service | URL | Purpose |
|---------|-----|---------|
| MongoDB Atlas | https://www.mongodb.com/cloud/atlas | Database |
| DockerHub | https://hub.docker.com | Image Registry |
| DigitalOcean | https://www.digitalocean.com | VPS |
| GitHub | https://github.com | Code + CI/CD |
| Cloudflare | https://www.cloudflare.com | CDN (FREE) |

---

## 💰 COST BREAKDOWN

```
┌─────────────────────────────────────────┐
│ DigitalOcean Droplet:    $24/month      │
│ MongoDB Atlas M0:        FREE           │
│ Cloudflare CDN:          FREE           │
│ GitHub Actions:          FREE           │
├─────────────────────────────────────────┤
│ TOTAL:                   $24/month      │
│ With $100 credit:        4+ months FREE │
└���────────────────────────────────────────┘
```

---

## 🔑 GITHUB SECRETS (6 Required)

```
DOCKERHUB_USERNAME    = your-dockerhub-username
DOCKERHUB_TOKEN       = your-dockerhub-token
VPS_HOST              = 123.45.67.89
VPS_USER              = root
VPS_PASSWORD          = your-vps-password
MONGODB_URI           = mongodb+srv://user:pass@cluster.mongodb.net/hypersend
```

---

## 📝 ENVIRONMENT VARIABLES (.env)

```env
MONGODB_URI=mongodb+srv://user:pass@cluster.mongodb.net/hypersend
SECRET_KEY=your-secret-key-32-chars-min
API_HOST=0.0.0.0
API_PORT=8000
API_BASE_URL=http://YOUR_VPS_IP:8000
DEBUG=False
ENVIRONMENT=production
DOCKERHUB_USERNAME=your-username
```

---

## 🌐 ACCESS POINTS (After Deployment)

```
API:           http://YOUR_VPS_IP:8000
API Docs:      http://YOUR_VPS_IP:8000/docs
Health:        http://YOUR_VPS_IP:8000/health
Frontend:      http://YOUR_VPS_IP:8550
```

---

## 🔧 ESSENTIAL COMMANDS

### SSH & Navigation
```bash
ssh root@YOUR_VPS_IP
cd /root/Hypersend
```

### Docker
```bash
docker-compose ps              # Check status
docker-compose logs backend    # View logs
docker-compose restart         # Restart
docker-compose down            # Stop
docker-compose up -d           # Start
```

### Monitoring
```bash
/root/monitor.sh               # System monitor
/root/health_check.sh          # Health check
docker stats                   # Docker stats
top                            # CPU/Memory
free -h                        # Memory
df -h                          # Disk
```

### Git
```bash
git pull origin main           # Update code
git add .                      # Stage changes
git commit -m "message"        # Commit
git push origin main           # Push (triggers deploy)
```

---

## ✅ VERIFICATION CHECKLIST

```
□ MongoDB Atlas cluster created
□ DockerHub account created
□ DigitalOcean droplet created
□ GitHub secrets added (6)
□ VPS setup completed
□ .env file configured
□ Repository cloned
□ GitHub Actions workflow completed
□ Containers running (docker-compose ps)
□ Health check passing (curl http://localhost:8000/health)
□ API docs accessible (http://YOUR_VPS_IP:8000/docs)
□ No errors in logs (docker-compose logs backend)
□ Monitoring scripts working (/root/monitor.sh)
```

---

## 🚨 COMMON ISSUES & QUICK FIXES

| Issue | Fix |
|-------|-----|
| Container won't start | `docker-compose logs backend` |
| Port already in use | `lsof -ti:8000 \| xargs kill -9` |
| MongoDB connection failed | Check MONGODB_URI in .env |
| GitHub Actions fails | Check GitHub Secrets |
| High CPU usage | `docker stats` to identify |
| Out of memory | Increase swap or upgrade |
| Disk full | `docker system prune -a -f` |

---

## 📊 PERFORMANCE TARGETS

```
Response Time:        < 500ms
Throughput:           1000+ req/sec
Concurrent Users:     20K-30K
Total Users:          1M+
Uptime:               99.9%
CPU Usage:            < 50%
Memory Usage:         < 70%
```

---

## 🔐 SECURITY CHECKLIST

```
□ Firewall enabled (ufw status)
□ SSH key authentication (recommended)
□ .env in .gitignore
□ Secrets in GitHub Secrets (not in code)
□ MongoDB password strong
□ IP whitelist configured
□ SSL/HTTPS ready (optional)
```

---

## 📈 SCALING STRATEGY

### When to Scale
- CPU > 80% consistently
- Memory > 85%
- Response time > 2 seconds
- Error rate > 1%

### Scaling Options
```
Option 1: Upgrade Droplet
  2 vCPU, 4GB → 4 vCPU, 8GB ($24 → $48/month)

Option 2: Add Load Balancer
  + Load Balancer ($12/month)
  + 2-3 additional droplets

Option 3: Upgrade Database
  MongoDB M0 (FREE) → M10 ($57/month)
```

---

## 📚 DOCUMENTATION FILES

| File | Purpose |
|------|---------|
| DEPLOYMENT_GUIDE_COMPLETE.md | Full step-by-step guide |
| DEPLOYMENT_CHECKLIST.md | Verification checklist |
| TROUBLESHOOTING.md | Common issues & solutions |
| COST_OPTIMIZATION.md | Budget optimization |
| QUICK_SETUP.sh | Automated setup script |
| README_DEPLOYMENT.md | Overview & navigation |

---

## 🎯 DEPLOYMENT TIMELINE

```
Preparation:        30 minutes
VPS Setup:          20 minutes
GitHub Config:      10 minutes
Deployment:         5 minutes
Verification:       10 minutes
─────────────────────────────
TOTAL:              75 minutes
```

---

## 💡 PRO TIPS

1. **Start small** - Use 2 vCPU, 4GB droplet ($24/month)
2. **Use free services** - MongoDB M0, Cloudflare, GitHub Actions
3. **Monitor early** - Setup monitoring from day 1
4. **Optimize first** - Before scaling up
5. **Backup regularly** - Database and code
6. **Test thoroughly** - Before going live
7. **Document everything** - For future reference
8. **Plan for growth** - Have scaling strategy ready

---

## 🆘 EMERGENCY CONTACTS

### If Something Goes Wrong

1. **Check logs first**
   ```bash
   docker-compose logs backend
   ```

2. **Run health check**
   ```bash
   /root/health_check.sh
   ```

3. **Restart services**
   ```bash
   docker-compose restart
   ```

4. **Check documentation**
   - TROUBLESHOOTING.md
   - DEPLOYMENT_GUIDE_COMPLETE.md

5. **System reset (last resort)**
   ```bash
   docker-compose down
   docker system prune -a -f
   docker-compose up -d
   ```

---

## 📞 USEFUL RESOURCES

- [DigitalOcean Docs](https://docs.digitalocean.com/)
- [Docker Docs](https://docs.docker.com/)
- [MongoDB Docs](https://docs.atlas.mongodb.com/)
- [GitHub Actions](https://docs.github.com/en/actions)
- [Nginx Docs](https://nginx.org/en/docs/)

---

## ✨ SUCCESS INDICATORS

Your deployment is successful when:

✅ `docker-compose ps` shows all containers "Up"
✅ `curl http://YOUR_VPS_IP:8000/health` returns 200
✅ `http://YOUR_VPS_IP:8000/docs` loads Swagger UI
✅ `docker-compose logs backend` shows no errors
✅ `/root/monitor.sh` shows healthy metrics
✅ GitHub Actions workflow completed successfully

---

## 🎉 YOU'RE READY!

**Next Steps:**
1. Read DEPLOYMENT_GUIDE_COMPLETE.md
2. Follow the step-by-step guide
3. Use DEPLOYMENT_CHECKLIST.md to verify
4. Monitor with /root/monitor.sh
5. Celebrate! 🎊

---

**Print this page for quick reference during deployment!**

*Last Updated: 2024*
*For Lakhs of Users with $100 DigitalOcean Credit*
