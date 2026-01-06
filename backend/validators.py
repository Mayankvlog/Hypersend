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
    
    # Command injection patterns - use regex for proper detection
    dangerous_patterns = [
        r'[;&|`$<>]',  # Shell metacharacters
        r'\|\|',       # OR command execution
        r'&&',         # AND command execution
        r'>>',         # Append redirection
        r'<<',         # Here document
        r'<\(',        # Process substitution
        r'\$\(',       # Command substitution
        r'\$\{',       # Parameter expansion
        r'eval\s*\(',  # eval function
        r'exec\s*\(',  # exec function
        r'system\s*\(', # system function
        r'popen\s*\(', # popen function
        r'shell\s*=\s*["\']?true["\']?',  # shell=True
        r'cat\s+/',    # cat system files
        r'passwd',      # password files
        r'shadow',     # shadow file
        r'hosts',       # hosts file
        r'crontab',     # cron jobs
        r'wget\s+',     # wget command
        r'curl\s+',     # curl command
        r'nc\s+',       # netcat command
        r'netcat',      # netcat
        r'chmod\s+',    # chmod command
        r'chown\s+',    # chown command
        r'rm\s+',       # rm command
        r'rmdir\s+',    # rmdir command
        r'mv\s+',       # mv command
        r'cp\s+',       # cp command
        r'dd\s+',       # dd command
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, input_string, re.IGNORECASE):
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
    - Path traversal attempts (../ or ..\\)
    - Null byte injection
    - Excessively long paths
    - Paths that escape allowed directory
    
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
    
    # Check for path traversal patterns - ZERO TOLERANCE FOR SECURITY
    # Block any ../ patterns regardless of count
    if re.search(r'\.\.[/\\]', file_path):
        return False
    
    # Block URL encoded path traversal attempts
    url_encoded_patterns = [
        r'%2e%2e%2f',  # ../ URL encoded
        r'%2e%2e%5c',  # ..\ URL encoded
        r'%2e%2e%2f%2e%2e%2f',  # ../../ URL encoded
        r'%c0%af',       # Unicode / bypass
        r'%c1%9c',       # Unicode \ bypass
        r'%252e%252e%252f',  # Double encoded ../
        r'%252e%252e%255c',  # Double encoded ..\
        r'..%252f..%252f..%252f',  # Mixed double encoded
        r'..%255c..%255c..%255c',  # Mixed double encoded backslash
    ]
    
    for pattern in url_encoded_patterns:
        if re.search(pattern, file_path, re.IGNORECASE):
            return False
    
    # Block Windows-specific traversal patterns
    if re.search(r'\.\.\\', file_path) or re.search(r'\\\.\\', file_path):
        return False
    
    # Additional checks for absolute paths or drive letters
    if file_path.startswith('/') or (len(file_path) > 1 and file_path[1] == ':'):
        return False
    
    # Block home directory traversal attempts
    if file_path.startswith('~') or re.search(r'~[^/\\\\]', file_path):
        return False
    
    # CONSOLIDATED UNC path and absolute path blocking
    # Combines multiple checks into single logical block for efficiency
    dangerous_path_patterns = [
        r'^\\\\',  # UNC path start
        r'^[a-zA-Z]:',  # Windows drive letter
    ]
    
    # Primary UNC detection - any double backslash sequence
    if '\\\\' in file_path:
        return False
    
    # Secondary pattern-based checks
    for pattern in dangerous_path_patterns:
        if re.match(pattern, file_path):
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
    
    # Remove HTML tags and content
    sanitized = re.sub(r'<script[^>]*>.*?</script>', '', sanitized, flags=re.IGNORECASE | re.DOTALL)
    sanitized = re.sub(r'<[^>]*>', '', sanitized)
    
    # Remove potentially dangerous characters and control sequences
    sanitized = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', sanitized)
    
    # Remove JavaScript and data URIs - more aggressive
    sanitized = re.sub(r'javascript\s*:', '', sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r'data\s*:', '', sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r'vbscript\s*:', '', sanitized, flags=re.IGNORECASE)
    
    # Remove JNDI injection patterns
    sanitized = re.sub(r'\$\{[^}]*\}', '', sanitized, flags=re.IGNORECASE)
    
    # Remove template injection patterns
    sanitized = re.sub(r'\{\{[^}]*\}\}', '', sanitized, flags=re.IGNORECASE)
    
    # Remove SQL injection patterns
    sanitized = re.sub(r"(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b)", '', sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"[;'\"]", '', sanitized)
    
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[<>"\'`]', '', sanitized)
    
    # Remove null bytes and control characters
    sanitized = re.sub(r'[\x00-\x1f\x7f]', '', sanitized)
    
    # Normalize whitespace
    sanitized = re.sub(r'\s+', ' ', sanitized)
    
    # Limit length
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    
    # Strip whitespace
    sanitized = sanitized.strip()
    
    return sanitized