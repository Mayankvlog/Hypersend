# Zaply APK - Configuration & Permissions Verification

## ✅ APK App Name Configuration

| Setting | Value | Status |
|---------|-------|--------|
| **Project Name** | Zaply | ✓ Configured |
| **Product Name** | Zaply | ✓ Configured |
| **Package/Organization** | com.zaply | ✓ Configured |
| **App Window Title** | Zaply | ✓ Configured |
| **Description** | Secure P2P File Transfer and Messaging | ✓ Set |

**Source**: `pyproject.toml` & `frontend/app.py`

---

## 🔐 Android Permissions (6 Total)

All 6 required permissions are configured and implemented:

### 1. **Location** 📍
- **Icon**: LOCATION_ON
- **Color**: #FF5252 (Red)
- **Description**: Allow access to your location for sharing
- **Status**: ✅ Enabled
- **Configuration**: `[tool.flet.android.permissions] location = true`

### 2. **Camera** 📷
- **Icon**: CAMERA_ALT
- **Color**: #42A5F5 (Blue)
- **Description**: Allow access to camera for video calls
- **Status**: ✅ Enabled
- **Configuration**: `[tool.flet.android.permissions] camera = true`

### 3. **Microphone** 🎤
- **Icon**: MIC
- **Color**: #AB47BC (Purple)
- **Description**: Allow access to microphone for voice calls
- **Status**: ✅ Enabled
- **Configuration**: `[tool.flet.android.permissions] microphone = true`

### 4. **Contacts** 👥
- **Icon**: CONTACTS
- **Color**: #29B6F6 (Cyan)
- **Description**: Allow access to your contacts
- **Status**: ✅ Enabled
- **Configuration**: `[tool.flet.android.permissions] contacts = true`

### 5. **Phone State** ☎️
- **Icon**: PHONE
- **Color**: #66BB6A (Green)
- **Description**: Allow reading phone state
- **Status**: ✅ Enabled
- **Configuration**: `[tool.flet.android.permissions] phone = true`

### 6. **Storage** 💾
- **Icon**: FOLDER
- **Color**: #FFA726 (Orange)
- **Description**: Allow access to files and media
- **Status**: ✅ Enabled
- **Configuration**: `[tool.flet.android.permissions] storage = true`

---

## 📋 Configuration Summary

### pyproject.toml (Build Configuration)
```toml
[tool.flet]
module_name = "app"
product = "Zaply"
project = "zaply"
org = "com.zaply"
description = "Secure P2P File Transfer and Messaging"
build_android_split_per_abi = true
android_architectures = ["arm64-v8a"]

[tool.flet.android.permissions]
location = true
camera = true
microphone = true
contacts = true
phone = true
storage = true
```

### Frontend Implementation
- **Main App**: `frontend/app.py`
  - Window title set to "Zaply"
  - App class: `ZaplyApp`
  
- **Permissions UI**: `frontend/views/permissions.py`
  - All 6 permissions with icons and descriptions
  - Allow/Disallow toggle for each permission
  - User-friendly permission management
  
- **Settings View**: `frontend/views/settings.py`
  - Permissions section integrated
  - User can manage permissions

---

## 🏗️ Build Instructions

### Building APK with All Permissions

```bash
# Standard Build (Recommended)
flet build apk --compile-app --cleanup-app --split-per-abi --verbose

# Minimal Build (Smallest)
flet build apk --compile-app --cleanup-app --arch arm64-v8a --verbose

# Using Build Script
python build_apk.py standard
```

### Expected Output
- **App Name**: "Zaply" (in app launcher and settings)
- **Package Name**: com.zaply.app
- **Permissions Requested**: All 6 permissions will be requested on first launch
- **Size**: 80-120 MB (with split-per-abi)

---

## 📱 Permission Request Flow

When user opens the Zaply app on Android:

1. ✅ **Location Permission** - Request for location access
2. ✅ **Camera Permission** - Request for camera access
3. ✅ **Microphone Permission** - Request for microphone access
4. ✅ **Contacts Permission** - Request for contacts access
5. ✅ **Phone State Permission** - Request for phone state access
6. ✅ **Storage Permission** - Request for file/media access

User can also manage permissions anytime in:
- App → Settings → App Permissions

---

## ✨ Status: PRODUCTION READY

- [x] App name set to "Zaply"
- [x] All 6 permissions configured
- [x] Permissions UI implemented
- [x] Build configuration complete
- [x] Documentation updated
- [x] Ready for APK build

**Last Updated**: December 2, 2025

**Built with**: Flet 0.28.3, Python 3.11+, FastAPI, MongoDB

---

**Next Step**: Run `flet build apk --compile-app --cleanup-app --split-per-abi --verbose` to generate the APK with all permissions included!
