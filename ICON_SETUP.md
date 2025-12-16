# Hypersend Icon Setup Guide

## Lightning Bolt Icon Configuration

This document describes how the Hypersend lightning bolt icon is configured across all platforms (Web, Android APK, Desktop, Linux, macOS).

### Icon File Locations

```
frontend/
├── assets/
│   ├── icon.png              # Main icon (used by Flutter/Flet)
│   └── favicon.ico           # Favicon for web browser tabs
├── web/
│   └── icons/
│       ├── Icon-192.png      # Web PWA icon 192x192
│       ├── Icon-512.png      # Web PWA icon 512x512
│       ├── Icon-maskable-192.png
│       └── Icon-maskable-512.png
├── android/app/src/main/res/
│   ├── mipmap-hdpi/launcher_icon.png
│   ├── mipmap-mdpi/launcher_icon.png
│   ├── mipmap-xhdpi/launcher_icon.png
│   ├── mipmap-xxhdpi/launcher_icon.png
│   └── mipmap-xxxhdpi/launcher_icon.png
├── windows/runner/resources/
│   └── app_icon.ico          # Windows desktop icon
├── linux/
│   └── my_application/       # Linux launcher configuration
└── macos/Runner/Assets.xcassets/
    └── AppIcon.appiconset/   # macOS app icon
```

### Icon Specifications

- **Format**: PNG (192x192, 512x512) for web/Android
- **ICO Format**: For Windows (.ico file)
- **Design**: Lightning bolt symbol (⚡) in cyan/blue color on rounded square background
- **Background**: Rounded square with gradient blue background

### Configuration Files

#### 1. **Web (Flutter Web)**
- **File**: `frontend/web/manifest.json`
- **Icon Path**: `web/icons/Icon-*.png`
- **Format**: PNG
- **Used for**: PWA manifest, browser tabs, bookmarks

#### 2. **Android (APK)**
- **Configuration**: `pyproject.toml` - `[tool.flet.android]`
- **Icon Dir**: `frontend/assets/` (referenced as `package_icons_dir`)
- **Icons**: `launcher_icon.png` in multiple DPI folders
- **Used for**: App launcher, app drawer

#### 3. **Desktop (Windows)**
- **File**: `frontend/windows/runner/resources/app_icon.ico`
- **Configuration**: `frontend/windows/runner/Runner.rc`
- **Format**: ICO (Windows Icon Format)
- **Used for**: Window title bar, taskbar, file associations

#### 4. **Desktop (Linux)**
- **File**: `frontend/linux/my_application/launcher.desktop`
- **Icon**: Referenced as Icon parameter
- **Used for**: Application launcher, file manager

#### 5. **Desktop (macOS)**
- **File**: `frontend/macos/Runner/Assets.xcassets/AppIcon.appiconset/`
- **Format**: PNG in various sizes (1024x1024, 512x512, etc.)
- **Used for**: Dock, Finder, macOS app launcher

### How to Update Icons

If you need to change the icon:

1. **Generate all sizes** from a single high-res PNG:
   - Use online tools or: `flutter pub run flutter_launcher_icons:main`
   - Or use ImageMagick: `convert original.png -resize 512x512 output-512.png`

2. **Replace files** in respective directories

3. **Update Android** (if using Flet):
   ```bash
   dart run flutter_app_badger
   ```

4. **Build APK** with new icons:
   ```bash
   flutter build apk --release
   ```

5. **Build Web**:
   ```bash
   flutter build web --release
   ```

6. **Build Desktop** (Windows):
   ```bash
   flutter build windows --release
   ```

### Current Icon Status

✓ Lightning bolt icon configured for all platforms
✓ Web PWA icons (192x192, 512x512)
✓ Android launcher icons (multiple DPI)
✓ Windows desktop icon (.ico)
✓ pyproject.toml points to icon locations

### Testing Icon Display

1. **Web**: Check browser tab icon
2. **APK**: Install on Android, check app drawer and launcher
3. **Windows**: Check app shortcut icon in Start Menu
4. **Linux**: Check application launcher
5. **macOS**: Check dock and Finder icons

### Notes

- The same lightning bolt design should be used across all platforms for consistent branding
- For Android, multiple DPI versions ensure the icon looks crisp on all screen densities
- Web icons must be PNG format for PWA compatibility
- Windows requires ICO format for native app appearance
