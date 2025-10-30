from fastapi import APIRouter, HTTPException
from typing import Dict, Any
from datetime import datetime
import json

router = APIRouter(prefix="/updates", tags=["Updates"])

# Store version info (in production, use database)
VERSION_INFO = {
    "1.0.0": {
        "version": "1.0.0",
        "build_number": 1,
        "release_date": "2025-01-28",
        "download_url": "https://your-server.com/downloads/hypersend-1.0.0.apk",
        "changelog": "Initial release with chat and file sharing features",
        "min_supported_version": "1.0.0",
        "force_update": False
    },
    "1.1.0": {
        "version": "1.1.0", 
        "build_number": 2,
        "release_date": "2025-02-01",
        "download_url": "https://your-server.com/downloads/hypersend-1.1.0.apk",
        "changelog": "Bug fixes and performance improvements\n- Fixed file upload issues\n- Improved chat UI\n- Better error handling",
        "min_supported_version": "1.0.0",
        "force_update": False
    }
}

LATEST_VERSION = "1.1.0"  # Update this when you release new version

@router.get("/check")
async def check_for_updates(current_version: str, platform: str = "android") -> Dict[str, Any]:
    """Check if updates are available"""
    
    if current_version not in VERSION_INFO:
        # Unknown version, recommend latest
        return {
            "update_available": True,
            "version": LATEST_VERSION,
            "download_url": VERSION_INFO[LATEST_VERSION]["download_url"],
            "changelog": VERSION_INFO[LATEST_VERSION]["changelog"],
            "force_update": True,
            "message": "Unknown version detected. Please update to the latest version."
        }
    
    if current_version == LATEST_VERSION:
        # Already latest version
        return {
            "update_available": False,
            "message": "You have the latest version"
        }
    
    # Update available
    latest_info = VERSION_INFO[LATEST_VERSION]
    current_info = VERSION_INFO[current_version]
    
    return {
        "update_available": True,
        "version": latest_info["version"],
        "download_url": latest_info["download_url"],
        "changelog": latest_info["changelog"],
        "release_date": latest_info["release_date"],
        "force_update": latest_info["force_update"],
        "current_version": current_version,
        "message": f"Update available: {current_version} → {LATEST_VERSION}"
    }

@router.get("/latest")
async def get_latest_version():
    """Get latest version info"""
    return VERSION_INFO[LATEST_VERSION]

@router.get("/version/{version}")
async def get_version_info(version: str):
    """Get specific version info"""
    if version not in VERSION_INFO:
        raise HTTPException(status_code=404, detail="Version not found")
    
    return VERSION_INFO[version]

@router.post("/release")
async def release_new_version(version_data: dict):
    """Release new version (admin only - add authentication)"""
    # In production, add proper authentication/authorization
    
    version = version_data.get("version")
    if not version:
        raise HTTPException(status_code=400, detail="Version is required")
    
    VERSION_INFO[version] = {
        "version": version,
        "build_number": version_data.get("build_number", 1),
        "release_date": datetime.utcnow().strftime("%Y-%m-%d"),
        "download_url": version_data.get("download_url"),
        "changelog": version_data.get("changelog", ""),
        "min_supported_version": version_data.get("min_supported_version", "1.0.0"),
        "force_update": version_data.get("force_update", False)
    }
    
    global LATEST_VERSION
    LATEST_VERSION = version
    
    return {"message": f"Version {version} released successfully"}