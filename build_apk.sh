#!/bin/bash

# Zaply APK Build Script for Linux/macOS
# Builds optimized APK with size reduction

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║     ZAPLY APK BUILD - SIZE OPTIMIZED (Linux/macOS)         ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}❌${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is not installed"
    exit 1
fi

print_status "Python found"

# Check if Flet is installed
python3 -c "import flet" 2>/dev/null
if [ $? -ne 0 ]; then
    print_error "Flet is not installed. Install it with: pip install flet"
    exit 1
fi

print_status "Flet found"
echo ""

# Step 1: Clean previous builds
echo "${YELLOW}[Step 1/5]${NC} Cleaning previous builds..."
rm -rf build .flet .gradle
print_status "Cleaned build directories"
echo ""

# Step 2: Clean Python cache
echo "${YELLOW}[Step 2/5]${NC} Cleaning Python cache..."
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null
find . -name "*.pyc" -delete 2>/dev/null
print_status "Cleaned Python cache"
echo ""

# Step 3: Choose build type
echo "${YELLOW}[Step 3/5]${NC} Choosing build type..."
echo ""
echo "Build options:"
echo "  1) standard - All architectures, optimized (~100MB)"
echo "  2) minimal  - ARM64 only (~70MB)"
echo "  3) split    - Separate per architecture (~50MB each)"
echo ""

BUILD_TYPE="standard"
if [ "$1" == "minimal" ]; then
    BUILD_TYPE="minimal"
elif [ "$1" == "split" ]; then
    BUILD_TYPE="split"
fi

case $BUILD_TYPE in
    minimal)
        echo "${GREEN}Selected: Minimal Build (ARM64 only)${NC}"
        echo ""
        echo "${YELLOW}[Step 4/5]${NC} Building APK (minimal)..."
        echo "Command: flet build apk --compile-app --cleanup-app --arch arm64-v8a --verbose"
        echo ""
        flet build apk --compile-app --cleanup-app --arch arm64-v8a --verbose
        ;;
    split)
        echo "${GREEN}Selected: Split Build (per architecture)${NC}"
        echo ""
        echo "${YELLOW}[Step 4/5]${NC} Building split APKs..."
        echo "Command: flet build apk --compile-app --cleanup-app --split-per-abi --verbose"
        echo ""
        flet build apk --compile-app --cleanup-app --split-per-abi --verbose
        ;;
    *)
        echo "${GREEN}Selected: Standard Build (all architectures)${NC}"
        echo ""
        echo "${YELLOW}[Step 4/5]${NC} Building APK with optimizations..."
        echo "Command: flet build apk --compile-app --cleanup-app --split-per-abi --verbose"
        echo ""
        flet build apk --compile-app --cleanup-app --split-per-abi --verbose
        ;;
esac

if [ $? -ne 0 ]; then
    echo ""
    print_error "APK build failed!"
    echo ""
    echo "Troubleshooting:"
    echo "  - Ensure Android SDK is installed"
    echo "  - Check ANDROID_SDK_ROOT environment variable"
    echo "  - Run: pip install --upgrade flet"
    exit 1
fi

echo ""
echo "${YELLOW}[Step 5/5]${NC} Build completed successfully!"
echo ""

# Display APK information
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                    APK BUILD COMPLETE                      ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

echo "APK Location: build/android/app/build/outputs/apk/release/"
echo ""
echo "APK Files:"
echo ""

# Find and display APK files with sizes
APK_DIR="build/android/app/build/outputs/apk/release"
if [ -d "$APK_DIR" ]; then
    for apk_file in "$APK_DIR"/*.apk; do
        if [ -f "$apk_file" ]; then
            filename=$(basename "$apk_file")
            size=$(du -h "$apk_file" | cut -f1)
            echo "  ✓ $filename"
            echo "    Size: $size"
            echo ""
        fi
    done
fi

echo "═══════════════════════════════════════════════════════════════"
echo ""
print_status "Your APK is ready to install!"
echo ""
echo "Next steps:"
echo "  1. Connect Android device via USB"
echo "  2. Enable USB debugging on device"
echo "  3. Run: adb install -r $APK_DIR/app-release.apk"
echo "  4. Or distribute APK to Google Play Store"
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo ""

exit 0
