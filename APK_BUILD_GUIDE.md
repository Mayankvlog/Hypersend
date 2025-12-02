# Zaply APK Build Commands - Size Optimization Guide

## 🚀 Quick Build Commands

### 1. **Standard APK Build (Recommended)**
```bash
flet build apk --product --obfuscate --split-per-abi
```

**What it does:**
- `--product`: Production mode (optimized)
- `--obfuscate`: Minifies code and removes debug symbols
- `--split-per-abi`: Creates separate APKs for different CPU architectures

**Expected Size:** 80-120 MB

---

### 2. **Minimal APK Build (Smallest Size)**
```bash
flet build apk --product --obfuscate
```

**What it does:**
- Creates single APK for ARM64 architecture
- Removes all debug information
- Minimal dependencies

**Expected Size:** 60-80 MB
**Limitation:** Works only on ARM64 devices

---

### 3. **Split APK Build (Fastest Install)**
```bash
flet build apk --product --obfuscate --split-per-abi
```

**What it does:**
- Separate APKs: arm64-v8a, armeabi-v7a, x86_64
- Users download only what they need
- Each APK smaller individually

**Expected Sizes:**
- `arm64-v8a.apk`: 50-70 MB
- `armeabi-v7a.apk`: 45-65 MB
- `x86_64.apk`: 50-70 MB

---

### 4. **Ultra-Optimized Build**
```bash
flet build apk --product --obfuscate --split-per-abi --no-web --verbose
```

**What it does:**
- All optimizations above
- Removes web assets
- Shows detailed build output

**Expected Size:** 70-100 MB (split)

---

## 📊 Size Optimization Techniques

### 1. **Remove Unused Assets**
```bash
# Remove test files
find . -name "test_*.py" -delete

# Remove __pycache__ directories
find . -type d -name "__pycache__" -exec rm -rf {} +

# Remove .pyc files
find . -name "*.pyc" -delete
```

### 2. **Optimize Images**
```bash
# Install pngquant for image compression
# On Windows: choco install pngquant
# On macOS: brew install pngquant
# On Linux: apt-get install pngquant

# Compress all PNG images
pngquant --force --ext .png 256 frontend/assets/*.png
```

### 3. **Use Python Script for Automated Build**
```bash
# Run the automated build script with size optimization
python build_apk.py standard    # Standard build
python build_apk.py minimal     # Minimal build (smallest)
python build_apk.py split       # Split build (fastest download)
```

---

## 🔧 Complete Build Workflow

### Step 1: Clean Build Environment
```bash
# Remove previous build files
rm -rf build .flet .gradle

# Clean pycache
find . -type d -name "__pycache__" -exec rm -rf {} +
find . -name "*.pyc" -delete
```

### Step 2: Optimize Assets
```bash
# Remove unnecessary files
rm -f frontend/assets/*.bak
rm -f frontend/assets/*.tmp

# Optimize images (if you have pngquant)
pngquant --force --ext .png 256 frontend/assets/*.png
```

### Step 3: Run Build
```bash
# Option A: Standard production build
flet build apk --product --obfuscate --split-per-abi --verbose

# Option B: Using Python script
python build_apk.py standard
```

### Step 4: Find APK
```bash
# APK location (after build)
# On Windows: build\android\app\build\outputs\apk\release\
# On Linux/macOS: build/android/app/build/outputs/apk/release/

# Check file sizes
ls -lh build/android/app/build/outputs/apk/release/*.apk
```

---

## 💾 Size Comparison

| Build Type | Size | Install Time | Compatibility |
|-----------|------|--------------|----------------|
| **Standard** | 80-120 MB | ~2 min | All devices |
| **Minimal** | 60-80 MB | ~1.5 min | ARM64 only |
| **Split** | 50-70 MB each | ~1 min | Device-specific |
| **Ultra-Optimized** | 70-100 MB | ~1.5 min | All devices |

---

## 🛠️ Advanced Options

### Build with Specific Android Version
```bash
flet build apk --product --obfuscate --android-api-level 34 --split-per-abi
```

### Build with Specific NDK Version
```bash
flet build apk --product --obfuscate --android-ndk-version 25.2.9519653 --split-per-abi
```

### Enable Verbose Output (for debugging)
```bash
flet build apk --product --obfuscate --split-per-abi --verbose
```

### Build with Specific Gradle Version
```bash
flet build apk --product --obfuscate --android-gradle-version 8.1.2 --split-per-abi
```

---

## 📝 Build Configuration in pyproject.toml

Your current configuration:

```toml
[tool.flet.android.permissions]
location = true
camera = true
microphone = true
contacts = true
phone = true
storage = true

[tool.flet.android.build_settings]
# Add these for smaller APK size:
# minify = true
# shrink_resources = true
```

---

## ⚡ Quick Reference Commands

### For Windows (PowerShell)
```powershell
# Clean and build
Remove-Item -Recurse -Force build, .flet, .gradle -ErrorAction SilentlyContinue
python build_apk.py standard
```

### For Linux/macOS (Bash)
```bash
# Clean and build
rm -rf build .flet .gradle
python build_apk.py standard
```

---

## 🔍 Checking APK Size After Build

### On Windows
```powershell
Get-Item build/android/app/build/outputs/apk/release/*.apk | 
  Select-Object Name, @{Name="Size(MB)";Expression={[math]::Round($_.Length/1MB,2)}}
```

### On Linux/macOS
```bash
ls -lh build/android/app/build/outputs/apk/release/*.apk | 
  awk '{print $9, "(" $5 ")"}'
```

---

## 🎯 Optimization Tips for Smaller APK

1. **Remove unused dependencies** from `requirements.txt`
2. **Use minimal Python packages** - only what's needed
3. **Compress images** before building (use pngquant)
4. **Remove test files** before building
5. **Clear cache** before building
6. **Use split APKs** for distribution (users download only what they need)
7. **Enable obfuscation** to reduce code size
8. **Use --product flag** for production optimization

---

## 📦 Expected APK Contents

Your Zaply APK includes:

```
App Size Breakdown:
├── Python Runtime:        30-40 MB
├── Flet Framework:        20-30 MB
├── Flask/FastAPI libs:    10-15 MB
├── Database drivers:      5-10 MB
├── Your Code:            2-5 MB
└── Assets/Resources:      5-10 MB
─────────────────────────
Total:                    70-100 MB
```

---

## ✅ Build Checklist

Before building, ensure:

- [ ] `pyproject.toml` is configured correctly
- [ ] All permissions are set to `true` (or as needed)
- [ ] No uncommitted changes in git
- [ ] Python virtual environment is activated
- [ ] All dependencies are installed (`pip install -r requirements.txt`)
- [ ] No `__pycache__` directories
- [ ] No test files in production build
- [ ] Images are optimized

---

## 🚀 One-Line Build Commands

### Quick Standard Build
```bash
python build_apk.py standard
```

### Quick Minimal Build (Smallest)
```bash
python build_apk.py minimal
```

### Quick Split Build (Fastest)
```bash
python build_apk.py split
```

### Manual Standard Build
```bash
flet build apk --product --obfuscate --split-per-abi --verbose
```

### Manual Minimal Build
```bash
flet build apk --product --obfuscate --verbose
```

---

## 📊 Size Optimization Results

| Action | Size Reduction |
|--------|----------------|
| Remove test files | -2 MB |
| Clean __pycache__ | -5 MB |
| Optimize images | -10 MB |
| Use --obfuscate | -15 MB |
| Use --product | -10 MB |
| Single architecture | -30 MB |
| **Total possible** | **~70 MB reduction** |

---

## 🐛 Troubleshooting Build Errors

### Build Fails on Step 1
```bash
# Clear all caches
rm -rf build .flet .gradle node_modules
pip install --upgrade flet
```

### APK Too Large
```bash
# Use split APK approach
python build_apk.py split

# Or use minimal build
python build_apk.py minimal
```

### Android SDK Not Found
```bash
# Set Android SDK path
export ANDROID_SDK_ROOT=$HOME/Android/Sdk
flet build apk --product --obfuscate --split-per-abi
```

---

## 📞 Support & Resources

- **Flet Documentation:** https://flet.dev/docs
- **Android Build Guide:** https://flet.dev/docs/guides/python/deploying-android-app
- **APK Size Optimization:** https://developer.android.com/topic/performance/reduce-app-size

---

## 🎉 After Build

Once APK is built:

1. **Locate the APK files:**
   ```bash
   find . -name "*.apk" -type f
   ```

2. **Check sizes:**
   ```bash
   ls -lh build/android/app/build/outputs/apk/release/*.apk
   ```

3. **Test on device:**
   ```bash
   adb install build/android/app/build/outputs/apk/release/app-release.apk
   ```

4. **Sign APK (for Google Play):**
   ```bash
   jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 \
     -keystore my-release-key.keystore \
     app-release.apk alias_name
   ```

---

**Ready to build your optimized APK!** 🚀
