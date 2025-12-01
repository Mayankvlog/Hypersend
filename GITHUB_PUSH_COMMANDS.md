# 📤 PUSH TO GITHUB - COPY & PASTE COMMANDS

## ONE-TIME SETUP (If first time)

```powershell
# Configure git (one-time only)
git config --global user.name "Mayankvlog"
git config --global user.email "mayank.kr0311@gmail.com"
```

---

## MAIN UPLOAD COMMANDS

Copy and paste these commands in PowerShell:

```powershell
# Step 1: Navigate to project
cd C:\Users\mayan\Downloads\Addidas\hypersend

# Step 2: Check current status
git status

# Step 3: Stage all changes
git add -A

# Step 4: Commit with message
git commit -m "chore: final VPS deployment configuration (139.59.82.105)

- Unified docker-compose.yml (was duplicated, now single file)
- Backend connects to authenticated MongoDB with credentials
- Frontend connects to Backend via VPS IP 139.59.82.105:8000
- All hardcoded IP references removed, using environment variables only
- App name standardized from 'Zaply' to 'Hypersend' everywhere
- File size limits standardized to 40GB (42949672960 bytes)
- Production validation enabled with security checks
- CORS configuration with DEBUG mode control
- Health checks on all Docker services
- Bridge network (172.20.0.0/16) for service discovery
- Persistent volumes for data retention (mongodb_data, mongodb_config)
- Comprehensive deployment guides included:
  * DEPLOYMENT_VPS_GUIDE.md
  * FINAL_DEPLOYMENT_STATUS.md
  * GITHUB_UPLOAD_INSTRUCTIONS.md
  * COMPLETE_STATUS_SUMMARY.md
- Ready for immediate production deployment on VPS 139.59.82.105"

# Step 5: Push to GitHub
git push origin main

# Step 6: Verify (should show success)
git log -1 --oneline
```

---

## VERIFICATION AFTER PUSH

### Check in PowerShell

```powershell
# Verify push was successful
git log -1 --oneline
# Should show your commit

# Check remote
git remote -v
# Should show: origin  https://github.com/Mayankvlog/Hypersend.git

# View recent commits
git log --oneline -5
```

### Check on GitHub Website

Open in browser: **https://github.com/Mayankvlog/Hypersend**

Should see:
- ✅ Latest commit with your message
- ✅ Files updated: .env, docker-compose.yml
- ✅ New files: DEPLOYMENT_VPS_GUIDE.md, FINAL_DEPLOYMENT_STATUS.md, GITHUB_UPLOAD_INSTRUCTIONS.md, COMPLETE_STATUS_SUMMARY.md
- ✅ Commit count incremented

---

## IF PUSH FAILS

### Error: "fatal: could not read Username for..."

**Solution**: Set up GitHub credentials

```powershell
# Option 1: Use Personal Access Token
git config --global credential.helper wincred
git credential fill
# Enter: https://github.com
# Username: Mayankvlog
# Password: [GitHub Personal Access Token]

# Option 2: Use SSH (recommended)
# 1. Generate SSH key: ssh-keygen -t ed25519 -C "mayank.kr0311@gmail.com"
# 2. Add to GitHub: Settings > SSH and GPG keys > New SSH key
# 3. Change git URL: git remote set-url origin git@github.com:Mayankvlog/Hypersend.git
# 4. Try push again: git push origin main
```

### Error: "hint: Updates were rejected because the remote contains work..."

**Solution**: Pull latest changes first

```powershell
# Fetch latest changes
git fetch origin

# Rebase your changes
git rebase origin/main

# Try push again
git push origin main
```

---

## POST-DEPLOYMENT (After GitHub Upload)

### Deploy to VPS 139.59.82.105

```bash
# SSH to VPS
ssh root@139.59.82.105

# Navigate to deployment directory
cd /opt/hypersend

# Clone the updated repository
git clone https://github.com/Mayankvlog/Hypersend.git .

# Start Docker services
docker-compose up -d

# Verify all services
docker-compose ps

# Check backend health
curl http://139.59.82.105:8000/health

# View logs
docker-compose logs -f

# Access services:
# Frontend: http://139.59.82.105:8550
# Backend:  http://139.59.82.105:8000
# Docs:     http://139.59.82.105:8000/docs
```

---

## OPTIONAL: Create Release Tag

```powershell
# Create version tag
git tag -a v1.0.0-vps-ready -m "Production VPS deployment ready (139.59.82.105)"

# Push tag to GitHub
git push origin v1.0.0-vps-ready

# View tags
git tag -l

# Delete tag (if needed)
# git tag -d v1.0.0-vps-ready
# git push origin --delete v1.0.0-vps-ready
```

---

## QUICK REFERENCE

| Command | What It Does |
|---------|-------------|
| `git status` | Show what's changed |
| `git add -A` | Stage all changes |
| `git commit -m "..."` | Save changes with message |
| `git push origin main` | Upload to GitHub |
| `git log -1` | View latest commit |
| `git remote -v` | Check GitHub URL |

---

## FILES BEING UPLOADED

```
✅ .env (updated with VPS configuration)
✅ docker-compose.yml (unified - was duplicate)
✅ backend/config.py (updated with CORS)
✅ backend/main.py (updated app name)
✅ backend/database.py (authenticated MongoDB)
✅ frontend/app.py (VPS configuration)
✅ frontend/api_client.py (environment variables)
✅ DEPLOYMENT_VPS_GUIDE.md (NEW)
✅ FINAL_DEPLOYMENT_STATUS.md (NEW)
✅ GITHUB_UPLOAD_INSTRUCTIONS.md (NEW)
✅ COMPLETE_STATUS_SUMMARY.md (NEW)
```

---

## FINAL CHECKLIST

Before running the commands:

- [x] All changes have been made
- [x] Files are saved
- [x] No syntax errors
- [x] Docker-compose.yml is unified
- [x] .env has VPS_IP=139.59.82.105
- [x] Ready to upload

---

## 🚀 YOU'RE READY!

Just copy and paste the main commands above and hit Enter.

Your Hypersend project will be uploaded to GitHub and ready for VPS deployment! 🎉

