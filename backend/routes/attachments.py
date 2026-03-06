"""
WhatsApp-Style Attachment Menu API
Provides 6 attachment categories matching WhatsApp UX
"""

from fastapi import APIRouter, HTTPException, status, Depends
from typing import List, Dict
from datetime import datetime, timezone

from backend.auth.utils import get_current_user

router = APIRouter(prefix="/attachments", tags=["attachments"])


# 6 WhatsApp-style attachment categories
ATTACHMENT_CATEGORIES: Dict[str, Dict] = {
    "photos_videos": {
        "id": "photos_videos",
        "label": "Photos & Videos",
        "icon": "image",
        "material_icon": "🖼️",
        "description": "Send photos and videos from your library",
        "mime_types": ["image/jpeg", "image/png", "image/gif", "image/webp", "video/mp4", "video/quicktime", "video/x-msvideo"]
    },
    "documents": {
        "id": "documents",
        "label": "Documents",
        "icon": "description",
        "material_icon": "📄",
        "description": "Send PDFs and documents",
        "mime_types": ["application/pdf", "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/vnd.ms-excel", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "text/plain"]
    },
    "camera": {
        "id": "camera",
        "label": "Camera",
        "icon": "videocam",
        "material_icon": "📷",
        "description": "Take a photo or video with your camera",
        "mime_types": ["image/jpeg", "image/png", "video/mp4"]
    },
    "audio": {
        "id": "audio",
        "label": "Audio",
        "icon": "audio",
        "material_icon": "🎵",
        "description": "Send audio files and voice messages",
        "mime_types": ["audio/mpeg", "audio/wav", "audio/ogg", "audio/aac", "audio/flac", "audio/mp4"]
    },
    "files": {
        "id": "files",
        "label": "Files",
        "icon": "folder",
        "material_icon": "📁",
        "description": "Send any file from your device",
        "mime_types": ["*/*"]  # Any file type
    }
}


@router.get("/categories")
async def get_attachment_categories(current_user: str = Depends(get_current_user)):
    """Get available WhatsApp-style attachment categories"""
    try:
        categories = [
            {
                "id": cat_id,
                "label": cat_data["label"],
                "icon": cat_data["icon"],
                "material_icon": cat_data["material_icon"],
                "description": cat_data["description"]
            }
            for cat_id, cat_data in ATTACHMENT_CATEGORIES.items()  
        ]
        
        return {
            "success": True,
            "categories": categories,
            "category_count": len(categories),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get attachment categories: {str(e)}"
        )


@router.get("/category/{category_id}")
async def get_attachment_category(
    category_id: str,
    current_user: str = Depends(get_current_user)
):
    """Get details for a specific attachment category"""
    try:
        # Validate category exists
        if category_id not in ATTACHMENT_CATEGORIES:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Attachment category '{category_id}' not found"
            )
        
        cat_data = ATTACHMENT_CATEGORIES[category_id]
        
        return {
            "success": True,
            "category": {
                "id": cat_data["id"],
                "label": cat_data["label"],
                "icon": cat_data["icon"],
                "material_icon": cat_data["material_icon"],
                "description": cat_data["description"],
                "mime_types": cat_data["mime_types"]
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get category: {str(e)}"
        )


@router.get("/mime-types")
async def get_mime_type_category(
    mime_type: str,
    current_user: str = Depends(get_current_user)
):
    """Get which category a MIME type belongs to"""
    try:
        mime_type = mime_type.lower().strip()
        
        # Find category for mime type
        for cat_id, cat_data in ATTACHMENT_CATEGORIES.items():
            mime_types = cat_data.get("mime_types", [])
            
            # Check exact match or wildcard
            if mime_type in mime_types or "*/*" in mime_types:
                return {
                    "success": True,
                    "mime_type": mime_type,
                    "category_id": cat_id,
                    "category": cat_data["label"],
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            
            # Check prefix match (e.g., image/* for image/png)
            prefix = mime_type.split("/")[0]
            if f"{prefix}/*" in mime_types:
                return {
                    "success": True,
                    "mime_type": mime_type,
                    "category_id": cat_id,
                    "category": cat_data["label"],
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
        
        # Default to files category
        return {
            "success": True,
            "mime_type": mime_type,
            "category_id": "files",
            "category": "Files",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to determine MIME type category: {str(e)}"
        )


@router.post("/validate")
async def validate_attachment(
    mime_type: str,
    file_size: int,
    current_user: str = Depends(get_current_user)
):
    """Validate if attachment is allowed for upload"""
    try:
        from backend.config import settings
        
        # Check file size limit
        max_size = settings.MAX_FILE_SIZE_BYTES
        if file_size > max_size:
            return {
                "success": False,
                "valid": False,
                "reason": f"File exceeds maximum size of {max_size / 1024 / 1024:.0f}MB",
                "max_size": max_size,
                "actual_size": file_size
            }
        
        # Check MIME type is in allowed categories
        mime_type = mime_type.lower().strip()
        allowed = False
        category = None
        
        for cat_id, cat_data in ATTACHMENT_CATEGORIES.items():
            mime_types = cat_data.get("mime_types", [])
            if mime_type in mime_types or "*/*" in mime_types:
                allowed = True
                category = cat_id
                break
            
            # Check prefix match
            prefix = mime_type.split("/")[0]
            if f"{prefix}/*" in mime_types:
                allowed = True
                category = cat_id
                break
        
        if not allowed:
            return {
                "success": False,
                "valid": False,
                "reason": f"MIME type '{mime_type}' not allowed",
                "mime_type": mime_type
            }
        
        return {
            "success": True,
            "valid": True,
            "mime_type": mime_type,
            "category": category,
            "file_size": file_size,
            "max_size": max_size,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Validation failed: {str(e)}"
        )
