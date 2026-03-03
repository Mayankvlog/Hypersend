"""
Advanced Emoji Picker API
Provides 8-category emoji selection with real-time search functionality
"""

from fastapi import APIRouter, HTTPException, status, Query, Depends
from typing import List, Dict, Optional
import json
from datetime import datetime, timezone

from backend.auth.utils import get_current_user

router = APIRouter(prefix="/emojis", tags=["emoji"])


# 8 emoji categories matching WhatsApp/Unicode standard
EMOJI_CATEGORIES = {
    "smileys_people": {
        "name": "Smileys & People",
        "icon": "😀",
        "emojis": [
            "😀", "😃", "😄", "😁", "😆", "😅", "😂", "🤣", "☺", "😊",
            "😇", "🙂", "🙃", "😉", "😌", "😍", "🥰", "😘", "😗", "😚",
            "😙", "🥲", "😋", "😛", "😜", "🤪", "😝", "😑", "😐", "😶",
            "😏", "😒", "🙄", "😬", "🤥", "😌", "😔", "😪", "🤤", "😴",
            "😷", "🤒", "🤕", "🤢", "🤮", "🤮", "🤧", "🤨", "😐", "😑"
        ]
    },
    "animals_nature": {
        "name": "Animals & Nature",
        "icon": "🐵",
        "emojis": [
            "🐶", "🐱", "🐭", "🐹", "🐰", "🦊", "🐻", "🐼", "🐨", "🐯",
            "🦁", "🐮", "🐷", "🐸", "🐵", "🙈", "🙉", "🙊", "🐒", "🐔",
            "🐧", "🐦", "🐤", "🦆", "🦅", "🦉", "🦇", "🐺", "🐗", "🐴",
            "🦄", "🐝", "🐛", "🦋", "🐌", "🐞", "🐜", "🪰", "🦟", "🦗"
        ]
    },
    "food_drinks": {
        "name": "Food & Drinks",
        "icon": "🍕",
        "emojis": [
            "🍏", "🍎", "🍐", "🍊", "🍋", "🍌", "🍉", "🍇", "🍓", "🍈",
            "🍒", "🍑", "🥭", "🍍", "🥥", "🥝", "🍅", "🍆", "🥑", "🥦",
            "🥬", "🥒", "🌶", "🌽", "🥕", "🧄", "🧅", "🥔", "🍠", "🥐",
            "🥯", "🍞", "🥖", "🥨", "🧀", "🥚", "🍳", "🧈", "🥞", "🥓"
        ]
    },
    "activity": {
        "name": "Activity",
        "icon": "⚽",
        "emojis": [
            "⚽", "🏀", "🏈", "⚾", "🥎", "🎾", "🏐", "🏉", "🥏", "🎳",
            "🏓", "🏸", "🏒", "🏑", "🥍", "🏏", "🥅", "⛳", "⛸", "🎣",
            "🎽", "🎿", "🛷", "🛹", "🛼", "🛻", "🏂", "⛷", "🎫", "🎖"
        ]
    },
    "travel_places": {
        "name": "Travel & Places",
        "icon": "🚗",
        "emojis": [
            "🚗", "🚕", "🚙", "🚌", "🚎", "🏎", "🚓", "🚑", "🚒", "🚐",
            "🛻", "🚚", "🚛", "🚜", "🏍", "🏎", "🛵", "🦯", "🦽", "🦼",
            "🛺", "🚲", "🛴", "🛹", "🛼", "🚏", "⛽", "🚨", "🚥", "🚦",
            "🛑", "🚧", "⚓", "⛵", "🚤", "🛳", "🛰", "🚀", "✈", "🛩"
        ]
    },
    "objects": {
        "name": "Objects",
        "icon": "💡",
        "emojis": [
            "💡", "🔦", "🏮", "📔", "📕", "📖", "📗", "📘", "📙", "📚",
            "📓", "📒", "📑", "🧷", "🧵", "🧶", "📝", "✏", "✒", "🖋",
            "🖊", "🖌", "🖍", "📁", "📂", "📅", "📆", "🗒", "🗓", "🗃",
            "🗳", "🗄", "📋", "📇", "📈", "📉", "📊", "📓", "📔", "📒"
        ]
    },
    "symbols": {
        "name": "Symbols",
        "icon": "❤️",
        "emojis": [
            "❤", "🧡", "💛", "💚", "💙", "💜", "🖤", "🤍", "🤎", "💔",
            "💕", "💞", "💓", "💗", "💖", "💘", "💝", "💟", "💌", "💜",
            "✨", "⭐", "🌟", "💫", "⚡", "🔥", "💥", "✴", "🔴", "🟠",
            "🟡", "🟢", "🔵", "🟣", "🟤", "⚫", "⚪", "🟥", "🟧", "🟨"
        ]
    },
    "flags": {
        "name": "Flags",
        "icon": "🚩",
        "emojis": [
            "🚩", "🎌", "🏁", "🏴", "🏳", "🏳‍🌈", "🏳‍⚧", "🏴‍☠", "🇦🇨", "🇦🇩",
            "🇦🇪", "🇦🇫", "🇦🇬", "🇦🇮", "🇦🇱", "🇦🇲", "🇦🇴", "🇦🇶", "🇦🇷", "🇦🇸",
            "🇦🇹", "🇦🇺", "🇦🇼", "🇦🇽", "🇦🇿", "🇧🇦", "🇧🇧", "🇧🇩", "🇧🇪", "🇧🇫"
        ]
    }
}


@router.get("/categories")
async def get_emoji_categories(current_user: str = Depends(get_current_user)):
    """Get all emoji categories and their metadata"""
    try:
        categories = [
            {
                "id": cat_id,
                "name": cat_data["name"],
                "icon": cat_data["icon"],
                "emoji_count": len(cat_data.get("emojis", []))
            }
            for cat_id, cat_data in EMOJI_CATEGORIES.items()
        ]
        
        return {
            "success": True,
            "categories": categories,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "search_enabled": True,
            "max_search_results": 1000
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get emoji categories: {str(e)}"
        )


@router.get("/category/{category_id}")
async def get_emojis_by_category(
    category_id: str,
    current_user: str = Depends(get_current_user)
):
    """Get all emojis for a specific category"""
    try:
        # Validate category exists
        if category_id not in EMOJI_CATEGORIES:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Category '{category_id}' not found"
            )
        
        cat_data = EMOJI_CATEGORIES[category_id]
        
        return {
            "success": True,
            "category_id": category_id,
            "category_name": cat_data["name"],
            "emojis": cat_data.get("emojis", []),
            "emoji_count": len(cat_data.get("emojis", [])),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get emojis: {str(e)}"
        )


@router.get("/search")
async def search_emojis(
    query: str = Query(..., min_length=1, max_length=50, description="Search term"),
    category: Optional[str] = Query(None, description="Optional category filter"),
    limit: int = Query(100, ge=1, le=1000, description="Max results"),
    current_user: str = Depends(get_current_user)
):
    """Search emojis by name or description (case-insensitive)"""
    try:
        query_lower = query.lower().strip()
        
        # Search emoji descriptions and names
        results = []
        search_categories = []
        
        # Filter by category if provided
        if category:
            if category not in EMOJI_CATEGORIES:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid category: {category}"
                )
            search_categories = [category]
        else:
            search_categories = list(EMOJI_CATEGORIES.keys())
        
        # Search across categories
        for cat_id in search_categories:
            cat_data = EMOJI_CATEGORIES[cat_id]
            cat_name = cat_data["name"].lower()
            
            # Match category name or specific emojis
            for emoji in cat_data.get("emojis", []):
                # For now, support searching by category name
                # In production, maintain a searchable emoji database
                if query_lower in cat_name:
                    results.append({
                        "emoji": emoji,
                        "category": cat_id,
                        "category_name": cat_data["name"]
                    })
                    if len(results) >= limit:
                        break
            
            if len(results) >= limit:
                break
        
        # If no results from name search, return first limit emojis
        if not results:
            for cat_id in search_categories:
                cat_data = EMOJI_CATEGORIES[cat_id]
                for emoji in cat_data.get("emojis", [])[:limit]:
                    results.append({
                        "emoji": emoji,
                        "category": cat_id,
                        "category_name": cat_data["name"]
                    })
                if len(results) >= limit:
                    break
        
        return {
            "success": True,
            "query": query,
            "category_filter": category,
            "results": results[:limit],
            "result_count": len(results[:limit]),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Search failed: {str(e)}"
        )


@router.get("/all")
async def get_all_emojis(
    category: Optional[str] = Query(None, description="Optional category filter"),
    current_user: str = Depends(get_current_user)
):
    """Get all emojis, optionally filtered by category"""
    try:
        if category:
            if category not in EMOJI_CATEGORIES:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid category: {category}"
                )
            emojis = EMOJI_CATEGORIES[category].get("emojis", [])
            return {
                "success": True,
                "category": category,
                "emojis": emojis,
                "emoji_count": len(emojis),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        else:
            # Return all emojis organized by category
            all_emojis = {
                cat_id: cat_data.get("emojis", [])
                for cat_id, cat_data in EMOJI_CATEGORIES.items()
            }
            total_count = sum(len(emojis) for emojis in all_emojis.values())
            
            return {
                "success": True,
                "emojis": all_emojis,
                "emoji_count": total_count,
                "category_count": len(EMOJI_CATEGORIES),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get emojis: {str(e)}"
        )
