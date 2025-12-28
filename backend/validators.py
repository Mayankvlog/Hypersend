import re
from bson import ObjectId
from typing import Optional, Union

def validate_user_id(user_id: str) -> Optional[ObjectId]:
    """
    Validate and convert user_id string to ObjectId.
    Returns ObjectId if valid, None otherwise.
    """
    if not user_id or not isinstance(user_id, str):
        return None
    
    # Remove any whitespace
    user_id = user_id.strip()
    
    # Basic format validation - should be 24 hex characters
    if not re.match(r'^[a-fA-F0-9]{24}$', user_id):
        return None
    
    try:
        return ObjectId(user_id)
    except Exception:
        return None

def safe_object_id_conversion(user_id: Union[str, ObjectId]) -> Optional[ObjectId]:
    """
    Safely convert user_id to ObjectId, handling both string and ObjectId inputs.
    """
    if isinstance(user_id, ObjectId):
        return user_id
    
    return validate_user_id(str(user_id))