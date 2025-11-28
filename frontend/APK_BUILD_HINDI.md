# HyperSend APK Build Guide (Hindi)

## 🚀 तेज़ तरीका - APK बनाने के लिए

```bash
cd frontend
python build_apk.py
```

बस! यह script automatically सब कुछ करेगा।

---

## 📱 Step-by-Step (मैन्युअल)

### 1. Dependencies Install करें

```bash
cd frontend
pip install -r requirements.txt --upgrade
```

### 2. Production Config Copy करें

```bash
copy .env.production .env
```

### 3. APK Build करें

```bash
flet build apk --release --optimize
```

**समय लगेगा:** पहली बार 10-15 मिनट, बाद में 3-5 मिनट

### 4. APK मिलेगा यहाँ:

```
frontend/build/apk/app-release.apk
```

---

## ⚡ किए गए Optimizations

✅ **Backend:** VPS से connect - `http://139.59.82.105:8000`
✅ **HTTP/2:** Fast requests के लिए enabled
✅ **Connection Pooling:** 20 simultaneous connections
✅ **Timeouts:** Optimized (15s connect, 45s read)
✅ **Debug Mode:** Disabled (production के लिए)
✅ **Release Build:** Optimized और fast

---

## 🐛 Problems और Solutions

### 1. Build बहुत slow है

**कारण:**
- पहली बार Flutter SDK download होता है (500MB)
- Windows Defender scan कर रहा है

**Solution:**
- Windows Defender में `frontend/build` folder को exclude करें
- अगली बार fast होगी (3-5 मिनट)

### 2. "Cannot connect to server" error

**Check करें:**
```bash
curl http://139.59.82.105:8000/health
```

अगर काम नहीं कर रहा:
- VPS पर backend चालू है या नहीं
- Port 8000 open है या नहीं

### 3. APK install नहीं हो रहा

**Solution:**
- Android phone में "Unknown Sources" allow करें
- Settings → Security → Install unknown apps
- पुराना app पहले uninstall करें

---

## 📊 Build Time Expect करें

| बार | समय | नोट |
|-----|------|------|
| पहली बार | 10-15 min | Flutter SDK download |
| दूसरी बार से | 3-5 min | Fast हो जाएगा |

---

## 🔧 Backend URL बदलना है?

1. Edit: `frontend/.env.production`
2. Change: `API_BASE_URL=http://YOUR_VPS_IP:8000`
3. Rebuild APK

---

## ✅ Test करने से पहले

- [ ] Backend चालू है VPS पर
- [ ] Login/Register test किया
- [ ] File upload test किया
- [ ] Real Android phone पर test किया
- [ ] Slow network (3G) पर test किया

---

## 📦 APK Distribute करने के लिए

**Option 1:** Direct Download
- Google Drive पर upload करें
- Dropbox पर upload करें
- अपनी website पर host करें

**Option 2:** App Stores
- APKPure
- F-Droid
- Play Store (requires $25 account)

---

## 🎯 APK Size: ~25-35 MB

काफी छोटा है, easily share कर सकते हैं।

---

## 💡 Important Tips

1. **Production में हमेशा `.env.production` use करें**
2. **DEBUG=False रखें production में**
3. **Backend URL correct है check करें**
4. **पहली बार slow होगा, घबराएँ नहीं**
5. **Windows Defender exclude करें fast build के लिए**

---

## 📞 Help चाहिए?

**Backend logs देखें:**
```bash
# VPS पर
journalctl -u hypersend-backend -f
```

**App logs देखें:**
```bash
# Phone connect करके
adb logcat | grep flutter
```

---

**सब कुछ optimize हो गया है! Ab APK fast बनेगा। 🚀**
