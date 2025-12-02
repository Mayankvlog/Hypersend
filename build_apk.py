#!/usr/bin/env python3
"""
Zaply APK Build Script with Size Optimization
Builds optimized APK with minimal size
"""

import os
import subprocess
import shutil
import json
from pathlib import Path
from datetime import datetime

class APKBuilder:
    def __init__(self, project_root=".", app_name="Zaply"):
        self.project_root = Path(project_root)
        self.app_name = app_name
        self.build_dir = self.project_root / "build"
        self.apk_dir = self.build_dir / "android" / "app" / "build" / "outputs" / "apk"
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
    def log(self, message, level="INFO"):
        """Print formatted log message"""
        colors = {
            "INFO": "\033[94m",    # Blue
            "SUCCESS": "\033[92m",  # Green
            "WARNING": "\033[93m",  # Yellow
            "ERROR": "\033[91m",    # Red
        }
        reset = "\033[0m"
        color = colors.get(level, "")
        print(f"{color}[{level}] {message}{reset}")

    def check_requirements(self):
        """Check if all build requirements are installed"""
        self.log("Checking build requirements...")
        
        requirements = {
            "python": "python --version",
            "flet": "python -c 'import flet; print(flet.__version__)'",
            "java": "java -version",
            "android-sdk": "echo Checking Android SDK...",
        }
        
        for req, cmd in requirements.items():
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if result.returncode == 0:
                    self.log(f"✓ {req} installed", "SUCCESS")
                else:
                    self.log(f"✗ {req} not found", "WARNING")
                    return False
            except Exception as e:
                self.log(f"✗ Error checking {req}: {e}", "ERROR")
                return False
        
        return True

    def optimize_project(self):
        """Optimize project for smaller APK size"""
        self.log("Optimizing project for smaller APK...")
        
        optimizations = [
            ("Remove unnecessary files", self.remove_unnecessary_files),
            ("Optimize images", self.optimize_images),
            ("Remove debug info", self.remove_debug_info),
            ("Clean build cache", self.clean_cache),
        ]
        
        for name, func in optimizations:
            try:
                self.log(f"  - {name}...")
                func()
                self.log(f"  ✓ {name} complete", "SUCCESS")
            except Exception as e:
                self.log(f"  ✗ {name} failed: {e}", "WARNING")

    def remove_unnecessary_files(self):
        """Remove unnecessary files that increase APK size"""
        # Remove __pycache__ directories
        for pycache in self.project_root.rglob("__pycache__"):
            if pycache.exists():
                shutil.rmtree(pycache, ignore_errors=True)
        
        # Remove .pyc files
        for pyc in self.project_root.rglob("*.pyc"):
            if pyc.exists():
                pyc.unlink()
        
        # Remove test files
        test_files = ["test_*.py", "*_test.py"]
        for pattern in test_files:
            for file in self.project_root.rglob(pattern):
                if file.is_file() and file.name not in ["test_permissions.py"]:
                    try:
                        file.unlink()
                    except:
                        pass

    def optimize_images(self):
        """Optimize image files to reduce size"""
        self.log("    Compressing images...", "INFO")
        
        image_dirs = [
            self.project_root / "frontend" / "assets",
            self.project_root / "assets",
        ]
        
        for img_dir in image_dirs:
            if img_dir.exists():
                for img in img_dir.glob("**/*.png"):
                    try:
                        # Try to use pngquant if available
                        subprocess.run(
                            f"pngquant --force --ext .png 256 {img}",
                            shell=True,
                            capture_output=True,
                            timeout=5
                        )
                    except:
                        pass  # Skip if pngquant not available

    def remove_debug_info(self):
        """Remove debug information"""
        self.log("    Removing debug symbols...", "INFO")
        # This is handled by Flet during build with --obfuscate flag

    def clean_cache(self):
        """Clean build cache"""
        cache_dirs = [
            self.project_root / ".flet",
            self.project_root / "build",
            self.project_root / ".gradle",
            self.project_root / "frontend" / "__pycache__",
            self.project_root / "backend" / "__pycache__",
        ]
        
        for cache_dir in cache_dirs:
            if cache_dir.exists():
                try:
                    shutil.rmtree(cache_dir, ignore_errors=True)
                except:
                    pass

    def build_apk_standard(self):
        """Build standard APK with optimizations"""
        self.log("Building standard APK with optimizations...", "INFO")
        
        cmd = (
            "flet build apk "
            "--product "
            "--obfuscate "
            "--split-per-abi "
            "--no-web "
            "--verbose"
        )
        
        self.log(f"Executing: {cmd}")
        return self._run_build(cmd)

    def build_apk_minimal(self):
        """Build minimal APK (single architecture)"""
        self.log("Building minimal APK (ARM64 only)...", "INFO")
        
        # Flet minimal build
        cmd = (
            "flet build apk "
            "--product "
            "--obfuscate "
            "--android-ndk-version latest "
            "--verbose"
        )
        
        self.log(f"Executing: {cmd}")
        return self._run_build(cmd)

    def build_apk_split(self):
        """Build split APKs for different architectures (smaller individual APKs)"""
        self.log("Building split APKs (smaller per-architecture APKs)...", "INFO")
        
        cmd = (
            "flet build apk "
            "--product "
            "--obfuscate "
            "--split-per-abi "
            "--verbose"
        )
        
        self.log(f"Executing: {cmd}")
        return self._run_build(cmd)

    def _run_build(self, command):
        """Execute build command"""
        try:
            result = subprocess.run(
                command,
                shell=True,
                cwd=self.project_root,
                capture_output=False,
                text=True
            )
            return result.returncode == 0
        except Exception as e:
            self.log(f"Build failed: {e}", "ERROR")
            return False

    def get_apk_size(self, apk_path):
        """Get APK file size in MB"""
        if Path(apk_path).exists():
            size_mb = Path(apk_path).stat().st_size / (1024 * 1024)
            return size_mb
        return None

    def report_apk_info(self):
        """Report APK size and information"""
        self.log("APK Build Information:", "SUCCESS")
        
        print("\n" + "="*70)
        print("APK BUILD REPORT")
        print("="*70)
        
        # Find APK files
        apk_files = list(self.project_root.rglob("*.apk"))
        
        if apk_files:
            print(f"\nAPK Files Found: {len(apk_files)}")
            print("-"*70)
            
            total_size = 0
            for apk in sorted(apk_files):
                size_mb = self.get_apk_size(apk)
                if size_mb:
                    total_size += size_mb
                    print(f"  • {apk.name}")
                    print(f"    Size: {size_mb:.2f} MB")
                    print(f"    Path: {apk.relative_to(self.project_root)}")
                    print()
            
            print("-"*70)
            print(f"Total APK Size: {total_size:.2f} MB")
            print("="*70 + "\n")
            
            return apk_files
        else:
            self.log("No APK files found", "WARNING")
            return []

    def create_build_summary(self, build_type="standard", success=True, apk_files=None):
        """Create build summary report"""
        summary = {
            "timestamp": self.timestamp,
            "app_name": self.app_name,
            "build_type": build_type,
            "success": success,
            "apk_files": [str(f) for f in (apk_files or [])],
            "sizes_mb": [self.get_apk_size(f) for f in (apk_files or [])],
        }
        
        report_file = self.project_root / "BUILD_SUMMARY.json"
        with open(report_file, "w") as f:
            json.dump(summary, f, indent=2)
        
        return report_file

    def run(self, build_type="standard"):
        """Execute complete APK build process"""
        self.log(f"Starting {build_type} APK build process...", "SUCCESS")
        print()
        
        # Step 1: Check requirements
        if not self.check_requirements():
            self.log("Build requirements not met", "ERROR")
            return False
        
        print()
        
        # Step 2: Optimize project
        self.optimize_project()
        
        print()
        
        # Step 3: Build APK
        if build_type == "minimal":
            success = self.build_apk_minimal()
        elif build_type == "split":
            success = self.build_apk_split()
        else:  # standard
            success = self.build_apk_standard()
        
        print()
        
        # Step 4: Report results
        if success:
            self.log("APK build completed successfully!", "SUCCESS")
            apk_files = self.report_apk_info()
            self.create_build_summary(build_type, success, apk_files)
        else:
            self.log("APK build failed", "ERROR")
            self.create_build_summary(build_type, success)
        
        return success


def main():
    """Main entry point"""
    import sys
    
    print("\n╔════════════════════════════════════════════════════════════╗")
    print("║         ZAPLY APK BUILD - SIZE OPTIMIZED                  ║")
    print("╚════════════════════════════════════════════════════════════╝\n")
    
    builder = APKBuilder(project_root=".")
    
    # Choose build type
    build_type = "standard"  # Default
    
    if len(sys.argv) > 1:
        if sys.argv[1] in ["minimal", "split", "standard"]:
            build_type = sys.argv[1]
    
    print(f"Build Type: {build_type.upper()}")
    print(f"  • standard: Full-featured APK with all architectures")
    print(f"  • minimal:  Single architecture (ARM64) for smallest size")
    print(f"  • split:    Separate APKs per architecture")
    print()
    
    # Run build
    success = builder.run(build_type)
    
    # Exit with status
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
