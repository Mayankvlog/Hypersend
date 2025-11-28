# HyperSend APK Build Guide - Production Optimized

## 🚀 Quick Build (Recommended)

```bash
cd frontend
python build_apk.py
```

This automated script will:
- ✅ Load production configuration
- ✅ Update all dependencies
- ✅ Clean old builds
- ✅ Build optimized release APK
- ✅ Show APK location and size

---

## 🛠️ Manual Build Process

### 1. Setup Environment

```bash
cd frontend

# Install dependencies with HTTP/2 support
pip install -r requirements.txt --upgrade

# Copy production config
copy .env.production .env
```

### 2. Verify Backend Connection

Test VPS backend connectivity:

```bash
curl http://139.59.82.105:8000/health
```

Expected response: `{"status":"healthy"}`

### 3. Build APK

```bash
# Standard build (5-7 minutes)
flet build apk

# Optimized build with all flags (recommended)
flet build apk --name HyperSend --org com.hypersend --release --optimize
```

### 4. Find Your APK

APK location: `frontend/build/apk/app-release.apk`

---

## ⚡ Performance Optimizations Applied

### 1. **Network Optimizations**
- ✅ HTTP/2 enabled for faster requests
- ✅ Connection pooling (20 max connections, 10 keepalive)
- ✅ Optimized timeouts:
  - Connect: 15s
  - Read: 45s
  - Write: 30s
  - Total: 60s

### 2. **App Optimizations**
- ✅ Debug mode disabled in production
- ✅ Release build with optimizations
- ✅ Reduced memory footprint
- ✅ Lazy loading for chat messages
- ✅ Connection reuse and keepalive

### 3. **Build Optimizations**
- ✅ Release mode (--release flag)
- ✅ Code optimization (--optimize flag)
- ✅ Removed debug symbols
- ✅ Minified resources

---

## 🔧 Configuration

### Backend URL
Currently configured for VPS: `http://139.59.82.105:8000`

To change backend:
1. Edit `frontend/.env.production`
2. Update `API_BASE_URL` value
3. Rebuild APK

### Enable Debug Mode (Development Only)
Edit `.env.production`:
```ini
DEBUG=True
```

**Warning:** Never use DEBUG mode in production builds!

---

## 📱 Testing Your APK

### On Emulator
```bash
# Install on Android emulator
adb install frontend/build/apk/app-release.apk

# View logs
adb logcat | grep flutter
```

### On Physical Device
1. Enable "Developer Options" on Android device
2. Enable "USB Debugging"
3. Connect device via USB
4. Run: `adb install frontend/build/apk/app-release.apk`

---

## 🐛 Troubleshooting

### Build is Slow (>10 minutes)
**Causes:**
- First build downloads Flutter SDK (~500MB)
- Gradle dependencies download
- Windows Defender scanning files

**Solutions:**
- Add frontend/build to Windows Defender exclusions
- Use SSD if possible
- Close unnecessary programs
- Subsequent builds will be faster (2-5 minutes)

### "Cannot connect to server" Error
**Check:**
1. VPS backend is running: `curl http://139.59.82.105:8000/health`
2. Port 8000 is open on VPS firewall
3. API_BASE_URL is correct in .env

**Fix:**
```bash
# On VPS
sudo ufw allow 8000
sudo systemctl restart hypersend-backend
```

### APK Install Failed
**Solutions:**
- Enable "Install from Unknown Sources" on Android
- Uninstall old version first
- Check APK file is not corrupted (should be 20-40MB)

### App Crashes on Launch
**Debug:**
```bash
# Connect device and run
adb logcat | grep -i error

# Common issues:
# - Backend URL wrong → Edit .env.production
# - Network timeout → Check internet connection
# - Permissions → Grant storage/network permissions
```

---

## 📊 Expected Build Times

| Phase | Duration | Notes |
|-------|----------|-------|
| First build | 8-15 min | Downloads Flutter SDK |
| Clean build | 5-8 min | After cleaning cache |
| Incremental | 2-5 min | Small changes only |
| Dependencies | 1-2 min | pip install |

**Total first-time build: ~10-15 minutes**
**Subsequent builds: ~3-5 minutes**

---

## 🎯 Size Optimization

Current APK size: **~25-35 MB**

Further reduction possible by:
- Removing unused assets
- Using ProGuard (advanced)
- Splitting APKs per architecture

---

## ✅ Pre-Release Checklist

Before distributing APK:

- [ ] Backend URL points to production VPS
- [ ] DEBUG=False in .env.production
- [ ] Test login/logout
- [ ] Test file upload/download
- [ ] Test on real Android device
- [ ] Check app permissions
- [ ] Test on slow network (3G)
- [ ] Verify app version number

---

## 📦 Distribution

### Option 1: Direct Download
Upload `app-release.apk` to:
- Your website
- Google Drive
- Dropbox
- GitHub Releases

### Option 2: Alternative App Stores
- APKPure
- F-Droid
- Amazon Appstore

### Option 3: Google Play Store
Requires:
- Google Play Developer account ($25 one-time)
- Signed APK with keystore
- Store listing and screenshots

---

## 🔐 Signing APK (For Play Store)

```bash
# Generate keystore
keytool -genkey -v -keystore hypersend.keystore -alias hypersend -keyalg RSA -keysize 2048 -validity 10000

# Build signed APK
flet build apk --release --optimize \
  --build-name 1.0.0 \
  --build-number 1 \
  --keystore hypersend.keystore \
  --keystore-password {{YOUR_PASSWORD}}
```

**⚠️ IMPORTANT:** Keep keystore file secure! You cannot update app without it.

---

## 📞 Support

Issues? Check:
- Backend logs: `journalctl -u hypersend-backend -f`
- Frontend logs: `adb logcat | grep flutter`
- Network: `curl -v http://139.59.82.105:8000/health`

---

**Happy Building! 🚀**
