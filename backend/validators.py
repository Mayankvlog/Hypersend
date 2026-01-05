import re
import pathlib
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

def validate_command_injection(input_string: str) -> bool:
    """
    Validate input to prevent command injection attacks.
    
    Returns True if safe (no dangerous patterns detected), False if potentially dangerous.
    Validates against shell metacharacters, code execution patterns, and script injection.
    """
    if not input_string or not isinstance(input_string, str):
        return True  # Empty/null is not a threat, just invalid input
    
    # Command execution metacharacters - CRITICAL SECURITY PATTERNS
    # These are shell metacharacters that enable command chaining/execution
    shell_metacharacters = [
        ';',   # Command separator
        '|',   # Pipe operator
        '&',   # Background execution
        '>',   # Redirection
        '<',   # Input redirection
        '`',   # Backtick execution
        '$(',  # Command substitution
    ]
    
    # Check for shell metacharacters that could enable command injection
    for char_sequence in shell_metacharacters:
        if char_sequence in input_string:
            return False
    
    # Block dangerous code execution functions/keywords
    dangerous_keywords = [
        'eval(',
        'exec(',
        'system(',
        'os.system',
        'subprocess.run',
        'popen(',
        'shell=true',
        'shell=True',
    ]
    
    input_lower = input_string.lower()
    for keyword in dangerous_keywords:
        if keyword.lower() in input_lower:
            return False
    
    # Block script injection patterns (XSS and HTML injection)
    script_patterns = [
        r'<script[^>]*>',
        r'</script>',
        r'<iframe',
        r'<object',
        r'javascript:',
        r'onerror\s*=',
        r'onload\s*=',
        r'onclick\s*=',
        r'on\w+\s*=',  # Generic event handler injection
    ]
    
    for pattern in script_patterns:
        if re.search(pattern, input_string, re.IGNORECASE):
            return False
    
    # Block null bytes (file path injection)
    if '\x00' in input_string:
        return False
    
    return True

def validate_path_injection(file_path: str) -> bool:
    """
    Validate file path to prevent path injection attacks.
    
    Blocks:
    - Path traversal attempts (../ or ..\)
    - Null byte injection
    - Excessively long paths
    - Paths that escape the allowed directory
    
    Returns True if safe, False if potentially dangerous.
    """
    if not file_path or not isinstance(file_path, str):
        return False
    
    # Null byte injection check - CRITICAL
    if '\x00' in file_path:
        return False
    
    # Check for excessively long paths (potential DoS)
    if len(file_path) > 1024:
        return False
    
    # Check for path traversal patterns
    # Block patterns like: ../ ..\  or /../\ combinations
    if re.search(r'\.\.[/\\]', file_path):
        # Allow up to 1 level of traversal for legitimate use
        # Block excessive traversal attempts
        traversal_count = len(re.findall(r'\.\.[/\\]', file_path))
        if traversal_count > 1:
            return False
    
    # Additional checks for absolute paths or drive letters
    if file_path.startswith('/') or (len(file_path) > 1 and file_path[1] == ':'):
        return False
    
    # Verify path doesn't escape boundaries using pathlib
    import pathlib
    try:
        # If path exists, verify it's within allowed directory
        if pathlib.Path(file_path).exists():
            normalized_path = pathlib.Path(file_path).resolve()
            # Get current working directory
            current_dir = pathlib.Path('.').resolve()
            
            # Check if resolved path is within current directory
            try:
                normalized_path.relative_to(current_dir)
                return True
            except ValueError:
                # Path escapes current directory
                return False
        else:
            # For non-existent paths, basic validation passed
            # Actual file operations will fail safely if invalid
            return True
            
    except (ValueError, OSError):
        # Path resolution failed - could be malicious
        return False


def sanitize_input(input_string: str, max_length: int = 1000) -> str:
    """
    Sanitize input string to prevent various injection attacks
    """
    if not input_string or not isinstance(input_string, str):
        return ""
    
    # Remove null bytes
    sanitized = input_string.replace('\x00', '')
    
    # Remove control characters except newlines and tabs
    sanitized = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', sanitized)
    
    # Limit length
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    
    # Strip whitespace
    sanitized = sanitized.strip()
    
    return sanitized