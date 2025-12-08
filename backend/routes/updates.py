from fastapi import APIRouter, HTTPException
from typing import Dict, Any
from datetime import datetime
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

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


# Typing indicators and online status tracking
USER_TYPING_STATUS = {}  # {user_id: {chat_id: timestamp}}
USER_ONLINE_STATUS = {}  # {user_id: {"last_seen": datetime, "is_online": bool}}


from fastapi import Depends
from auth.utils import get_current_user


@router.post("/typing")
async def set_typing_status(
    chat_id: str,
    is_typing: bool,
    current_user: str = Depends(get_current_user)
):
    """Update typing status in a chat"""
    if current_user not in USER_TYPING_STATUS:
        USER_TYPING_STATUS[current_user] = {}
    
    if is_typing:
        USER_TYPING_STATUS[current_user][chat_id] = datetime.utcnow()
    else:
        USER_TYPING_STATUS[current_user].pop(chat_id, None)
    
    return {
        "status": "updated",
        "user_id": current_user,
        "chat_id": chat_id,
        "is_typing": is_typing
    }


@router.get("/typing/{chat_id}")
async def get_typing_users(chat_id: str):
    """Get users currently typing in a chat"""
    typing_users = []
    
    for user_id, chats in USER_TYPING_STATUS.items():
        if chat_id in chats:
            # Check if typing status is still valid (not older than 5 seconds)
            if (datetime.utcnow() - chats[chat_id]).total_seconds() < 5:
                typing_users.append(user_id)
    
    return {"chat_id": chat_id, "typing_users": typing_users}


@router.post("/online-status")
async def set_online_status(
    current_user: str = Depends(get_current_user)
):
    """Update user online status"""
    USER_ONLINE_STATUS[current_user] = {
        "last_seen": datetime.utcnow(),
        "is_online": True
    }
    
    return {"status": "online", "user_id": current_user}


@router.post("/offline-status")
async def set_offline_status(
    current_user: str = Depends(get_current_user)
):
    """Mark user as offline"""
    if current_user in USER_ONLINE_STATUS:
        USER_ONLINE_STATUS[current_user]["is_online"] = False
        USER_ONLINE_STATUS[current_user]["last_seen"] = datetime.utcnow()
    
    return {"status": "offline", "user_id": current_user}


@router.get("/user-status/{user_id}")
async def get_user_status(user_id: str):
    """Get user online status and last seen"""
    status_info = USER_ONLINE_STATUS.get(user_id, {
        "is_online": False,
        "last_seen": None
    })
    
    return {
        "user_id": user_id,
        "is_online": status_info.get("is_online", False),
        "last_seen": status_info.get("last_seen")
    }