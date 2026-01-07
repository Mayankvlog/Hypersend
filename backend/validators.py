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
    Note: SQL injection should be prevented through parameterized queries, not text filtering.
    """
    if not input_string or not isinstance(input_string, str):
        return True  # Empty/null is not a threat, just invalid input
    
    # Block dangerous shell patterns - ZERO tolerance for shell metacharacters
    dangerous_shell_patterns = [
        '||', '&&', ';', '|', '$(', '${', '`', '>', '<', '>>', '&'  # Shell metacharacters
    ]
    
    if any(pattern in input_string for pattern in dangerous_shell_patterns):
        return False
    
    # Block dangerous system paths that appear anywhere in input
    dangerous_system_paths = [
        'cat /etc/passwd',  # Direct cat of passwd file
        'cat /etc/shadow',  # Direct cat of shadow file  
        'rm /etc/passwd',  # Direct rm of system file
        'rm -rf /',        # Destructive command
        '/etc/passwd',     # Just the path
        '/etc/shadow',     # Shadow file
    ]
    
    for dangerous_path in dangerous_system_paths:
        if dangerous_path in input_string:
            return False
    
    # Block dangerous command patterns (must have arguments following)
    # These patterns match commands that indicate command execution with network access or system modification
    dangerous_commands = [
        r'\bsudo\s+',         # sudo usage
        r'\beval\s*\(',       # eval function call
        r'\bexec\s*\(',       # exec function call
        r'\bsystem\s*\(',     # system function call
        r'\bpopen\s*\(',      # popen function call
        r'\bos\.system',      # Python os.system
        r'\bsubprocess\.',    # Python subprocess module
        r'\bshell\s*=\s*(?:True|true|yes|1)\b', # shell=True parameter
        r'\bwget\s+',         # wget command with arguments (network access)
        r'\bcurl\s+',         # curl command with arguments (network access)
        r'\bnc\s+',           # netcat command with arguments (network access)
        r'\bchmod\s+\d',      # chmod with numeric permissions
        r'\bchown\s+',        # chown command (privilege modification)
        r'\bkill\s+',         # kill command
    ]
    
    for pattern in dangerous_commands:
        if re.search(pattern, input_string, re.IGNORECASE):
            return False
    
    # Block SQL injection patterns - only block clear injection attempts
    sql_patterns = [
        r"'\s*or\s*'1'\s*=\s*'1",  # Classic SQL injection
        r"'\s*or\s*1\s*=\s*1",     # SQL injection without quotes
        r'\bdelete\s+from\b',        # DELETE FROM 
        r'\bunion\s+select\b',       # UNION SELECT
        r'\binsert\s+into\b',        # INSERT INTO (suspicious context)
        r'\bupdate\s+\w+\s+set\b',  # UPDATE ... SET (suspicious context)
        r'\bexec\s*\(',             # SQL EXEC
        r'\bexecute\s*\(',          # SQL EXECUTE
    ]
    
    for pattern in sql_patterns:
        if re.search(pattern, input_string, re.IGNORECASE):
            return False
    
    # Block script/XSS injection patterns
    script_patterns = [
        r'<\s*script',              # <script tag
        r'javascript\s*:',          # javascript: protocol
        r'on\w+\s*=',              # Event handler (onerror=, onload=, etc.)
        r'<\s*iframe',              # <iframe tag
        r'<\s*object',              # <object tag
        r'<\s*embed',               # <embed tag
        r'data:\s*text/html',       # data: URI with HTML
    ]
    
    for pattern in script_patterns:
        if re.search(pattern, input_string, re.IGNORECASE):
            return False
    
    # Block null bytes (file path injection)
    if '\x00' in input_string:
        return False
    
    # Block control characters (except whitespace)
    if re.search(r'[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]', input_string):
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
    Sanitize input string to prevent various injection attacks.
    Remove null/control chars and neutralize dangerous patterns while preserving length.
    """
    if not input_string or not isinstance(input_string, str):
        return ""
    
    sanitized = input_string[:max_length]
    sanitized = sanitized.replace('\x00', '')
    sanitized = re.sub(r'[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]', '', sanitized)
    
    # Neutralize dangerous patterns by replacing with spaces of equal length
    patterns = [
        r'<\s*script[^>]*>.*?</\s*script\s*>',
        r'<\s*iframe[^>]*>.*?</\s*iframe\s*>',
        r'<\s*object[^>]*>.*?</\s*object\s*>',
        r'<\s*embed[^>]*>.*?</\s*embed\s*>',
        r'javascript:',
        r'vbscript:',
        r'data:\s*text/html',
        r'\bdrop\s+table\b',
        r'\bdelete\s+from\b',
        r'\bunion\s+select\b',
        r'on\w+\s*=',  # event handlers
        r'script',
        r'\$\{',
        r'\{\{',
    ]
    for pat in patterns:
        matches = list(re.finditer(pat, sanitized, flags=re.IGNORECASE | re.DOTALL))
        if matches:
            parts = []
            last = 0
            for m in matches:
                parts.append(sanitized[last:m.start()])
                parts.append(' ' * (m.end() - m.start()))
                last = m.end()
            parts.append(sanitized[last:])
            sanitized = ''.join(parts)
    
    # Explicitly strip template/shell markers that may remain
    sanitized = sanitized.replace('${', ' ').replace('{{', ' ').replace('}}', ' ')
    
    # Replace remaining angle brackets to prevent HTML execution while keeping length
    sanitized = sanitized.replace('<', ' ')
    sanitized = sanitized.replace('>', ' ')
    
    return sanitized