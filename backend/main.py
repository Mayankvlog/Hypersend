from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status, HTTPException, Depends
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response, JSONResponse
from fastapi.middleware.trustedhost import TrustedHostMiddleware
import logging
from pathlib import Path
import os
import sys
import asyncio
from dotenv import load_dotenv

# Load environment variables FIRST before importing config
print("[STARTUP] Loading environment variables...")
env_paths = [
    Path(__file__).parent / ".env",
    Path(__file__).parent.parent / ".env"
]

for env_path in env_paths:
    if env_path.exists():
        print(f"[STARTUP] Loading .env from: {env_path}")
        load_dotenv(dotenv_path=env_path)
        break
else:
    print("[STARTUP] No .env file found, using environment variables")

# Early diagnostic logging
print("[STARTUP] Python version:", sys.version)
print("[STARTUP] Python path:", sys.path)
print("[STARTUP] Current working directory:", os.getcwd())
print("[STARTUP] Starting backend imports...")

# Debug environment variables
print(f"[DEBUG] SECRET_KEY env var: {os.getenv('SECRET_KEY')}")
print(f"[DEBUG] DEBUG env var: {os.getenv('DEBUG')}")

try:
    # Add current directory to Python path for Docker
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent))
    from datetime import datetime, timezone
    
    # SECURITY: Prevent importing config with missing secrets in production
    if not os.getenv('SECRET_KEY') and not os.getenv('DEBUG', 'false').lower() in ('true', '1'):
        print(f"[DEBUG] SECRET_KEY env var: {os.getenv('SECRET_KEY')}")
        print(f"[DEBUG] DEBUG env var: {os.getenv('DEBUG')}")
        raise RuntimeError("PRODUCTION SAFETY: SECRET_KEY must be set in production")
    
    from config import settings
    if settings.USE_MOCK_DB:
        from mock_database import connect_db, close_db
        print("[STARTUP] + Using mock database module")
    else:
        from database import connect_db, close_db
        print("[STARTUP] + database module imported")
except Exception as e:
    print(f"[STARTUP] X Failed to import database: {e}")
    raise

try:
    from routes import auth, files, chats, users, updates, p2p_transfer, groups, messages, channels, debug
    print("[STARTUP] + routes modules imported")
except Exception as e:
    print(f"[STARTUP] X Failed to import routes: {e}")
    raise

try:
    from config import settings
    print("[STARTUP] + config module imported")
    print(f"[STARTUP] MongoDB URI (sanitized): {settings.MONGODB_URI.split('@')[-1] if '@' in settings.MONGODB_URI else 'invalid'}")
    print(f"[STARTUP] DEBUG mode: {settings.DEBUG}")
except Exception as e:
    print(f"[STARTUP] X Failed to import config: {e}")
    raise

try:
    from mongo_init import ensure_mongodb_ready
    print("[STARTUP] + mongo_init module imported")
except Exception as e:
    print(f"[STARTUP] X Failed to import mongo_init: {e}")
    raise

try:
    from security import SecurityConfig
    print("[STARTUP] + security module imported")
except Exception as e:
    print(f"[STARTUP] X Failed to import security: {e}")
    raise

try:
    from error_handlers import register_exception_handlers
    print("[STARTUP] + error_handlers module imported")
except Exception as e:
    print(f"[STARTUP] X Failed to import error_handlers: {e}")
    raise

print("[STARTUP] All imports successful!")


# ===== VALIDATION MIDDLEWARE FOR 4XX ERROR HANDLING =====
from starlette.middleware.base import BaseHTTPMiddleware
from datetime import datetime, timezone

class RequestValidationMiddleware(BaseHTTPMiddleware):
    """Enhanced middleware to validate requests and prevent common 4xx errors with security"""
    
    async def dispatch(self, request, call_next):
        """Validate request before processing with enhanced security checks"""
        try:
            # SECURITY: Check for malicious request patterns
            url_path = str(request.url.path)
            
            # Enhanced suspicious pattern detection with more comprehensive coverage
            # Immediate fix: Allow localhost and production domain requests
            def is_localhost_or_production(request):
              """Check if request is from localhost, Docker internal, or production domain"""
              client_host = request.client.host if request.client else ''
              host_header = request.headers.get('host', '').lower()
              localhost_patterns = ['localhost', '127.0.0.1', '0.0.0.0', '::1', 'hypersend_frontend', 'hypersend_backend', 'frontend', 'backend']
              production_patterns = ['zaply.in.net', 'www.zaply.in.net']
              return (any(pattern in client_host for pattern in localhost_patterns) or any(pattern in host_header for pattern in production_patterns))

            suspicious_patterns = [
                # Path traversal attacks
                '../', '..\\', '%2e%2e', '%2e%2e%2f', '%2e%2e%5c', 
                '..%2f', '..%5c', '%2e%2e/', '%2e%2e\\',
                '....//', '....\\\\', '%252e%252e%252f',
                
                # Script injection attacks
                '<script', '</script>', 'javascript:', 'vbscript:', 'data:', 
                'onload=', 'onerror=', 'onclick=', 'onmouseover=',
                'eval(', 'alert(', 'confirm(', 'prompt(',
                
                # SQL injection attacks  
                'union select', 'drop table', 'delete from', 'insert into',
                'update set', 'create table', 'alter table', 'exec sp_',
                '1\' or \'1\'=\'1', '1" or "1"="1', "admin'--",
                "' or 1=1--", '" or 1=1--', "'; drop table--",
                
                # XML/XXE injection attacks
                '<?xml', '<!doctype', '<svg', '<!entity', 'xlink:href=',
                '<xsl:stylesheet', 'external-entitiy', '<!ATTLIST',
                
                # System file access attempts
                '../../etc/passwd', '/etc/passwd', '/etc/shadow', '/etc/hosts',
                'c:\\windows\\system32', 'c:\\windows\\system32\\config',
                '/proc/version', '/proc/self/environ', '/etc/passwd%00',
                'cmd.exe', 'powershell', 'bash', 'sh', '/bin/', '/usr/bin/',
                'wget ', 'curl ', 'nc ', 'netcat ', 'perl ',
                
                # Command injection attempts
                '; rm -rf', '| cat /etc/passwd', '&& ls -la', '|| id',
                '`whoami`', '$(id)', '${jndi:ldap', '${env:HOME}',
                
                # NoSQL/Document injection
                '{$ne:}', '{$gt:}', '{$where:}', '$regex:', '$expr:',
                '{"$gt":""}', '{"$ne":null}', "'; return db.admin.find('",
                
                # LDAP injection
                '*)(', '*)(uid=*', '*)(|(uid=', '*)(password=*',
                '*)%00', '*)(&(objectClass=',
                
                # Log4j/RCE attempts
                '${jndi:', '${lower:jndi:', '${upper:jndi:', '${::-:j',
                '${env:', '${java:', '${sys:', '${log4j:',
                
                # Server-Side Template Injection
                '{{7*7}}', '${7*7}', '#{7*7}', '<%=7*7%>',
                '{{config}}', '${config}', '#{config}',
                
                # XXE payload variants
                '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
                '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE test',
                
                # Common web shell patterns
                'webshell', 'shell.php', 'cmd.jsp', 'aspshell',
                'eval(base64', 'system($_POST', 'passthru($_',
                'shell_exec($_', 'exec($_POST', 'preg_replace eval',
                
                # SSRF patterns (but allow localhost for health checks and development)
                '169.254.169.254', 'metadata.google.internal',
                'file:///', 'gopher://', 'dict://',
                # Note: 127.0.0.1, localhost, ::1, 0.0.0.0 are allowed for legitimate requests
                
                # Deserialization attacks
                'O:4:"User"', 'ACED0005', 'rO0ABX', '80ACED0',
                'ys0yPC', 'base64_decode', 'unserialize(',
                
                # Header injection
                'CRLF-injection', '%0d%0a', '\r\n', '%0D%0A',
                'X-Forwarded-For:', 'X-Real-IP:', 'X-Originating-IP:',
            ]
            
            url_lower = url_path.lower()
            headers_lower = {k.lower(): v.lower() if v else '' for k, v in dict(request.headers).items()}
            
            # Enhanced security check with localhost/loopback exception for legitimate requests
            def is_localhost_or_internal():
                """Check if request is from localhost or internal Docker network"""
                client_host = request.client.host if request.client else ''
                # Allow common localhost patterns for legitimate health checks and development
                localhost_patterns = [
                    'localhost', '127.0.0.1', '0.0.0.0', '::1',
                    'hypersend_frontend', 'hypersend_backend', 'frontend', 'backend'
                ]
                
                # Also check for production domain in host header
                host_header = request.headers.get('host', '').lower()
                production_patterns = ['zaply.in.net', 'www.zaply.in.net']
                
                return (any(pattern in client_host for pattern in localhost_patterns) or
                        any(pattern in host_header for pattern in production_patterns))
            
            is_internal = is_localhost_or_internal()
            
            # Check URL path for suspicious patterns (but allow legitimate localhost and production requests)
            # Always allow health check endpoint
            if url_path in ['/health', '/api/v1/health']:
                is_internal = True  # Force internal for health checks
                
            for pattern in suspicious_patterns:
                # Skip localhost-related patterns for internal requests
                if pattern in ['localhost', '127.0.0.1', '0.0.0.0', '::1'] and is_internal:
                    continue
                    
                # Skip production domain patterns
                if pattern in ['zaply.in.net'] and 'zaply.in.net' in url_lower:
                    continue
                    
                if pattern in url_lower and not is_internal:
                    logger.warning(f"[SECURITY] Suspicious URL blocked: {pattern} in {url_path}")
                    return JSONResponse(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        content={
                            "status_code": 400,
                            "error": "Bad Request - Malicious request detected",
                            "detail": "Request contains potentially malicious content",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "path": url_path,
                            "method": request.method,
                            "hints": ["Remove malicious content", "Check request format", "Ensure proper encoding"]
                        }
                    )
            
            # Check headers for suspicious patterns (but allow common legitimate headers and localhost)
            for header_name, header_value in headers_lower.items():
                # Skip checking certain safe headers
                safe_headers = ['user-agent', 'accept', 'content-type', 'authorization', 'host', 'x-forwarded-for', 'x-real-ip']
                if header_name in safe_headers:
                    continue
                    
                # Special handling for host header - allow localhost for legitimate requests
                if header_name == 'host':
                    # Allow common localhost patterns in host header for health checks and development
                    allowed_host_patterns = [
                        '169.254.169.254',
                        'hypersend_frontend', 'hypersend_backend', 'frontend', 'backend',
                        'zaply.in.net', 'www.zaply.in.net'  # Allow your production domain
                    ]
                    if any(allowed in header_value for allowed in allowed_host_patterns):
                        continue
                    
                for pattern in suspicious_patterns:
                    # Skip localhost-related patterns for internal requests
                    if pattern in ['localhost', '127.0.0.1', '0.0.0.0', '::1'] and is_internal:
                        continue
                        
                    # Skip production domain patterns  
                    if pattern in ['zaply.in.net'] and 'zaply.in.net' in header_value:
                        continue
                        
                    if pattern in header_value:
                        logger.warning(f"[SECURITY] Suspicious header blocked: {pattern} in {header_name}")
                        return JSONResponse(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            content={
                                "status_code": 400,
                                "error": "Bad Request - Malicious header detected",
                                "detail": "Request header contains potentially malicious content",
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "path": url_path,
                                "method": request.method,
                                "hints": ["Remove malicious content", "Check request headers", "Ensure proper encoding"]
                            }
                        )
            
            # Check Content-Length for POST/PUT/PATCH (411)
            if request.method in ["POST", "PUT", "PATCH"]:
                content_length_header = request.headers.get("content-length")
                
                if not content_length_header and request.method != "GET":
                    # Try to check if there's a body without Content-Length
                    try:
                        body = await request.body()
                        if body and not content_length_header:
                            # Log but allow (fastapi might handle)
                            import logging
                        logging.getLogger(__name__).warning(f"[411] Missing Content-Length for {request.method} {request.url.path}")
                    except Exception as e:
                        logger.warning(f"[MIDDLEWARE_ERROR] Content-Length header parsing error: {str(e)}")
                
                # Check payload size (413)
                if content_length_header:
                    try:
                        content_length = int(content_length_header)
                        max_size = 5 * 1024 * 1024 * 1024  # 5GB limit
                        if content_length > max_size:
                            return JSONResponse(
                                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                                content={
                                    "status_code": 413,
                                    "error": "Payload Too Large - Request body is too big",
                                    "detail": f"Request size {content_length} bytes exceeds maximum {max_size} bytes",
                                    "timestamp": datetime.now(timezone.utc).isoformat(),
                                    "path": url_path,
                                    "method": request.method,
                                    "hints": ["Reduce file size", "Use chunked uploads", "Check server limits"]
                                }
                            )
                    except ValueError:
                        return JSONResponse(
                            status_code=status.HTTP_411_LENGTH_REQUIRED,
                            content={
                                "status_code": 411,
                                "error": "Length Required - Content-Length header is invalid",
                                "detail": "Content-Length header must be a valid integer",
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "path": url_path,
                                "method": request.method,
                                "hints": ["Provide valid Content-Length", "Ensure header is a number"]
                            }
                        )
            
            # Check URL length (414)
            url_length = len(str(request.url))
            if url_length > 8000:  # RFC 7230 recommendation
                return JSONResponse(
                    status_code=status.HTTP_414_URI_TOO_LONG,
                    content={
                        "status_code": 414,
                        "error": "URI Too Long - The requested URL is too long",
                        "detail": f"URL length {url_length} exceeds maximum 8000 characters",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "path": url_path,
                        "method": request.method,
                        "hints": ["Shorten the URL", "Use POST for complex queries"]
                    }
                )
            
            # Enhanced Content-Type validation for POST/PUT/PATCH
            if request.method in ["POST", "PUT", "PATCH"]:
                content_type = request.headers.get("content-type", "")
                if not content_type:
                    # Some requests can work without explicit Content-Type, but log for security
                    logger.debug(f"[SECURITY] No Content-Type for {request.method} {request.url.path}")
                else:
                    # Check for dangerous content types
                    dangerous_content_types = [
                        'application/x-msdownload',     # Executable download
                        'application/x-msdos-program',   # DOS executable
                        'application/x-executable',      # Generic executable
                        'application/x-shockwave-flash',  # Flash (deprecated, risky)
                        'text/html',                    # HTML in API requests (XSS risk)
                        'application/javascript',         # JavaScript in non-JS endpoints
                        'text/javascript',              # JavaScript in non-JS endpoints
                    ]
                    
                    content_type_lower = content_type.lower()
                    for dangerous_type in dangerous_content_types:
                        if dangerous_type in content_type_lower:
                            logger.warning(f"[SECURITY] Dangerous content-type blocked: {content_type}")
                            return JSONResponse(
                                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                                content={
                                    "status_code": 415,
                                    "error": "Unsupported Media Type - Content type not allowed",
                                    "detail": f"Content type '{content_type}' is not permitted for security reasons",
                                    "timestamp": datetime.now(timezone.utc).isoformat(),
                                    "path": str(request.url.path),
                                    "method": request.method,
                                    "hints": ["Use supported content types", "Check API documentation", "Ensure proper file format"]
                                }
                            )
            
            # Enhanced request size validation for different endpoints
            if request.method in ["POST", "PUT", "PATCH"]:
                content_length = request.headers.get("content-length")
                if content_length:
                    try:
                        size = int(content_length)
                        # Endpoint-specific size limits
                        url_path = str(request.url.path).lower()
                        
                        # Login/register endpoints - smaller limit
                        if '/auth/' in url_path or '/login' in url_path or '/register' in url_path:
                            max_size = 1024 * 1024  # 1MB
                            if size > max_size:
                                return JSONResponse(
                                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                                    content={
                                        "status_code": 413,
                                        "error": "Payload Too Large - Auth request too big",
                                        "detail": f"Authentication requests must be less than {max_size} bytes",
                                        "timestamp": datetime.now(timezone.utc).isoformat(),
                                        "path": str(request.url.path),
                                        "method": request.method,
                                        "hints": ["Reduce request size", "Check for file uploads", "Use appropriate endpoints"]
                                    }
                                )
                        
                        # Profile/Settings endpoints - medium limit
                        elif '/profile' in url_path or '/settings' in url_path:
                            max_size = 5 * 1024 * 1024  # 5MB
                            if size > max_size:
                                return JSONResponse(
                                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                                    content={
                                        "status_code": 413,
                                        "error": "Payload Too Large - Profile data too big",
                                        "detail": f"Profile requests must be less than {max_size} bytes",
                                        "timestamp": datetime.now(timezone.utc).isoformat(),
                                        "path": str(request.url.path),
                                        "method": request.method,
                                        "hints": ["Reduce profile data size", "Compress images", "Remove unnecessary data"]
                                    }
                                )
                        
                        # File upload endpoints - handled by file-specific logic
                        # This is just an additional safety net
                        elif '/files/' in url_path and '/upload' in url_path:
                            max_size = 5 * 1024 * 1024 * 1024  # 5GB safety net (should be enforced elsewhere)
                            if size > max_size:
                                return JSONResponse(
                                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                                    content={
                                        "status_code": 413,
                                        "error": "Payload Too Large - File too big",
                                        "detail": f"File uploads must be less than {max_size} bytes",
                                        "timestamp": datetime.now(timezone.utc).isoformat(),
                                        "path": str(request.url.path),
                                        "method": request.method,
                                        "hints": ["Use smaller files", "Compress large files", "Split large files"]
                                    }
                                )
                    except ValueError:
                        pass  # Invalid content-length handled elsewhere
            
            response = await call_next(request)
            
            # Enhanced response security headers
            security_headers = {
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "X-XSS-Protection": "1; mode=block",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Content-Security-Policy": "default-src 'none'; script-src 'none'; object-src 'none';",
                "X-Permitted-Cross-Domain-Policies": "none",
                "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
            }
            
            # Add security headers to response
            for header, value in security_headers.items():
                response.headers[header] = value
            
            return response
            
        except HTTPException:
            # Re-raise HTTPException to be handled by specific handlers
            raise
        except Exception as e:
            # Enhanced error logging with security context
            client_ip = request.client.host if request.client else "unknown"
            user_agent = request.headers.get("User-Agent", "unknown")
            
            logger.error(
                f"[MIDDLEWARE_ERROR] {request.method} {request.url.path} | "
                f"Client: {client_ip} | User-Agent: {user_agent[:100]} | "
                f"Error: {type(e).__name__}: {str(e)}", 
                exc_info=True
            )
            
            # Enhanced error classification
            error_str = str(e).lower()
            if any(keyword in error_str for keyword in ["validation", "json", "parse", "syntax"]):
                return JSONResponse(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    content={
                        "status_code": 422,
                        "error": "Unprocessable Entity - Invalid input data",
                        "detail": str(e) if settings.DEBUG else "Invalid input data",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "path": str(request.url.path),
                        "method": request.method,
                        "hints": ["Check request format", "Verify JSON syntax", "Review API documentation"]
                    }
                )
            elif any(keyword in error_str for keyword in ["timeout", "deadline", "deadlineexceeded"]):
                return JSONResponse(
                    status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                    content={
                        "status_code": 504,
                        "error": "Gateway Timeout - Request took too long",
                        "detail": str(e) if settings.DEBUG else "Request timeout",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "path": str(request.url.path),
                        "method": request.method,
                        "hints": ["Try again later", "Reduce request complexity", "Check server load"]
                    }
                )
            elif any(keyword in error_str for keyword in ["connection", "network", "unreachable"]):
                return JSONResponse(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    content={
                        "status_code": 503,
                        "error": "Service Unavailable - Connection issue",
                        "detail": str(e) if settings.DEBUG else "Service temporarily unavailable",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "path": str(request.url.path),
                        "method": request.method,
                        "hints": ["Check network connection", "Try again later", "Verify server status"]
                    }
                )
            else:
                return JSONResponse(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    content={
                        "status_code": 500,
                        "error": "Internal Server Error",
                        "detail": "Server error processing request" if not settings.DEBUG else str(e),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "path": str(request.url.path),
                        "method": request.method,
                        "hints": ["This is a server error", "Try again later", "Contact support if persistent"]
                    }
                )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup and shutdown events"""
    # Startup
    try:
        print(f"[START] Zaply API starting on {settings.API_HOST}:{settings.API_PORT}")
        print(f"[START] Environment: {'DEBUG' if settings.DEBUG else 'PRODUCTION'}")
        
        # Initialize directories first
        try:
            settings.init_directories()
        except Exception as e:
            print(f"[WARN] Directory initialization warning: {str(e)}")
        
        print("[DB] Initializing MongoDB...")
        
        # Initialize MongoDB (create users, collections, indexes)
        if not settings.USE_MOCK_DB:
            try:
                result = await ensure_mongodb_ready()
                if result:
                    print("[DB] MongoDB initialization completed successfully")
                else:
                    print("[DB] MongoDB initialization skipped or incomplete - will initialize on first use")
            except Exception as e:
                print(f"[WARN] MongoDB initialization warning: {str(e)}")
                print("[WARN] Continuing startup - collections will be created on first use")
        else:
            print("[DB] Using mock database - skipping MongoDB initialization")
        
        print(f"[DB] Connecting to MongoDB...")
        
        # Validate production settings
        try:
            settings.validate_production()
        except ValueError as ve:
            print(f"[ERROR] Configuration validation failed: {str(ve)}")
            raise
        except Exception as e:
            print(f"[ERROR] Unexpected validation error: {str(e)}")
            raise
        
        # Connect to database with retry logic
        max_db_retries = 5
        db_connected = False
        for db_attempt in range(max_db_retries):
            try:
                await connect_db()
                print("[DB] SUCCESS Database connection established successfully")
                db_connected = True
                break
            except Exception as e:
                if db_attempt < max_db_retries - 1:
                    print(f"[DB] Connection attempt {db_attempt + 1}/{max_db_retries} failed, retrying in 2 seconds...")
                    await asyncio.sleep(2)
                else:
                    if settings.USE_MOCK_DB:
                        print("[DB] SUCCESS Mock database initialized (no real DB needed)")
                        db_connected = True
                    else:
                        print(f"[ERROR] Database connection failed after {max_db_retries} attempts")
                        print(f"[ERROR] Details: {str(e)}")
                        if 'MONGODB_URI' not in os.environ:
                            print("[ERROR] MONGODB_URI not found in environment variables!")
                        raise
        
        if db_connected:
            print("[START] SUCCESS Server startup complete - Ready to accept requests")
        
        if settings.DEBUG:
            print(f"[START] Zaply API running in DEBUG mode on {settings.API_HOST}:{settings.API_PORT}")
            print("[CORS] Allowing all origins (DEBUG mode)")
        else:
            print("[START] Zaply API running in PRODUCTION mode")
            print("[CORS] Restricted to configured origins")
        
        print("[START] Lifespan startup complete, all services ready")
        print("[START] Backend is fully operational")
        
        yield
        
        print("[SHUTDOWN] Lifespan shutdown starting")
    except Exception as e:
        print(f"[ERROR] CRITICAL: Failed to start backend - {str(e)}")
        print(f"[ERROR] Ensure MongoDB is running: {settings.MONGODB_URI}")
        raise
    finally:
        # Shutdown
        print("[SHUTDOWN] Cleaning up resources")
        await close_db()
        print("[SHUTDOWN] All cleanup complete")


# Setup logger
logger = logging.getLogger("hypersend")
logger.setLevel(logging.INFO)

app = FastAPI(
    title="Zaply API",
    description="Secure peer-to-peer file transfer and messaging application",
    version="1.0.0",
    lifespan=lifespan,
    redirect_slashes=False  # Fix: Prevent automatic trailing slash redirects
)

# Register custom exception handlers
register_exception_handlers(app)

# Add validation middleware for 4xx error handling (411, 413, 414, 415)
app.add_middleware(RequestValidationMiddleware)

# Add a comprehensive catch-all exception handler for any unhandled exceptions
@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """
    Enhanced catch-all exception handler for unhandled exceptions
    
    LOGIC:
    - HTTPException: Already handled by specific handlers, re-raise
    - Timeout/Connection errors: 504 Gateway Timeout / 503 Service Unavailable
    - Database errors: 503 Service Unavailable
    - File system errors: 500 Internal Server Error / 507 Insufficient Storage
    - Validation errors: 400 Bad Request
    - Security errors: 401/403 Forbidden
    - Other errors: 500 Internal Server Error
    
    SECURITY: Don't expose internal details in production mode
    LOGIC: Provide specific error handling for common exception types
    """
    # Don't catch HTTPException - let the specific handler deal with those
    if isinstance(exc, HTTPException):
        raise exc  # Re-raise HTTPException to be handled by its specific handler
    
    import traceback
    import asyncio
    import pymongo.errors
    from pymongo.errors import PyMongoError
    
    # Enhanced logging with full context
    logger.error(
        f"[UNCAUGHT_EXCEPTION] {request.method} {request.url.path} | "
        f"{type(exc).__name__}: {str(exc)} | "
        f"Client: {request.client.host if request.client else 'Unknown'}",
        exc_info=True
    )
    
    # Determine appropriate status code and message based on exception type
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    error_msg = "Internal server error"
    hints = ["Try again in a moment", "Contact support if the problem persists"]
    
    # Enhanced exception type handling
    if isinstance(exc, asyncio.TimeoutError):
        status_code = status.HTTP_504_GATEWAY_TIMEOUT
        error_msg = "Request timeout - operation took too long"
        hints = ["Check your network connection", "Try with a smaller request", "Try again later"]
        
    elif isinstance(exc, ConnectionError):
        status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        error_msg = "Service temporarily unavailable - cannot connect to external service"
        hints = ["Check your internet connection", "Try again in a few moments", "Verify service status"]
        
    elif isinstance(exc, PyMongoError):
        if "timeout" in str(exc).lower():
            status_code = status.HTTP_504_GATEWAY_TIMEOUT
            error_msg = "Database timeout - operation took too long"
        elif "connection" in str(exc).lower():
            status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            error_msg = "Database connection failed - service temporarily unavailable"
        elif "duplicate" in str(exc).lower():
            status_code = status.HTTP_409_CONFLICT
            error_msg = "Resource already exists - duplicate entry detected"
        else:
            status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            error_msg = "Database error - service temporarily unavailable"
        hints = ["Try again in a few moments", "Check your request data", "Contact support if persistent"]
        
    elif isinstance(exc, (OSError, IOError)):
        error_msg_lower = str(exc).lower()
        if "no space left" in error_msg_lower or "disk full" in error_msg_lower:
            status_code = status.HTTP_507_INSUFFICIENT_STORAGE
            error_msg = "Server storage full - cannot complete operation"
        elif "permission denied" in error_msg_lower:
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            error_msg = "Server permission error - please contact support"
        elif "network unreachable" in error_msg_lower:
            status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            error_msg = "Network service unavailable - please check connection"
        else:
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            error_msg = "Server I/O error - please try again"
        hints = ["Try again with smaller data", "Contact support if persistent"]
        
    elif isinstance(exc, ValueError):
        status_code = status.HTTP_400_BAD_REQUEST
        error_msg = "Invalid input data - check your request parameters"
        hints = ["Check request format and data types", "Verify all required fields are provided"]
        
    elif isinstance(exc, KeyError):
        status_code = status.HTTP_400_BAD_REQUEST
        error_msg = "Missing required field in request"
        hints = ["Check that all required fields are provided", "Review API documentation"]
        
    elif isinstance(exc, (AttributeError, TypeError)):
        status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        error_msg = "Internal server error - data processing failed"
        hints = ["This is a server issue", "Try again later", "Contact support if persistent"]
        
    # Security-related exceptions
    elif "unauthorized" in str(exc).lower() or "authentication" in str(exc).lower():
        status_code = status.HTTP_401_UNAUTHORIZED
        error_msg = "Authentication required or invalid credentials"
        hints = ["Check your authentication token", "Login again if session expired"]
        
    elif "forbidden" in str(exc).lower() or "permission" in str(exc).lower():
        status_code = status.HTTP_403_FORBIDDEN
        error_msg = "Access denied - insufficient permissions"
        hints = ["Check your access permissions", "Contact administrator for access"]
    
    # Prepare response data
    response_data = {
        "status_code": status_code,
        "error": type(exc).__name__ if settings.DEBUG else error_msg.title(),
        "detail": error_msg if not settings.DEBUG else str(exc),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "path": str(request.url.path),
        "method": request.method,
        "hints": hints,
    }
    
    # Add specific context for certain error types
    if status_code == 413:
        response_data["max_size"] = "5GB"
    elif status_code == 429:
        response_data["retry_after"] = "60"
    
    # Add security headers to all error responses
    security_headers = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Cache-Control": "no-cache, no-store, must-revalidate",  # Don't cache errors
    }
    
    return JSONResponse(
        status_code=status_code,
        content=response_data,
        headers=security_headers
    )

# Add 404 handler for non-existent endpoints
@app.exception_handler(404)
async def not_found_handler(request: Request, exc: HTTPException):
    """Handle 404 Not Found errors - resource or endpoint doesn't exist"""
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={
            "status_code": 404,
            "error": "Not Found",
            "detail": "The requested resource doesn't exist. Check the URL path.",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "path": str(request.url.path),
            "method": request.method,
            "hints": ["Check the URL spelling", "Verify the endpoint exists", "Review API documentation"]
        }
    )

# Add 405 handler for method not allowed
@app.exception_handler(405)
async def method_not_allowed_handler(request: Request, exc: HTTPException):
    """
    Handle 405 Method Not Allowed errors - endpoint exists but HTTP method not supported
    
    SECURITY: Use strict HTTP method validation to prevent bypass attacks
    LOGIC: Only return 405 if endpoint exists with different method
    """
    path = str(request.url.path)
    method = request.method
    
    # SECURITY FIX: Check for path traversal attempts and suspicious patterns
    # Reject paths with parent directory traversal (..), double slashes (//) or other bypass attempts
    if '..' in path or path.startswith('//') or '%2e%2e' in path.lower():
        # These are clearly malicious paths - return 404 instead of 405
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={
                "status_code": 404,
                "error": "Not Found",
                "detail": "Invalid path format - the requested resource doesn't exist.",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "path": path,
                "method": method,
                "hints": ["Verify the correct endpoint path", "Check for special characters", "Review API documentation"]
            }
        )
    
    # LOGIC FIX: Check if ANY route exists at this path with a different method
    matching_routes = [
        route for route in app.routes 
        if hasattr(route, 'path') and (route.path == path.rstrip('/') or route.path == path)
    ]
    
    # If no routes match this path, it's 404 not 405
    if not matching_routes:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={
                "status_code": 404,
                "error": "Not Found",
                "detail": "The requested endpoint doesn't exist.",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "path": path,
                "method": method,
                "hints": ["Check the URL spelling", "Verify the endpoint exists", "Review API documentation"]
            }
        )
    
    # If route exists but method is wrong, return 405 with allowed methods
    allowed_methods = set()
    for route in matching_routes:
        if hasattr(route, 'methods'):
            allowed_methods.update(route.methods)
    
    # Always add OPTIONS for CORS
    allowed_methods.add("OPTIONS")
    
    return JSONResponse(
        status_code=status.HTTP_405_METHOD_NOT_ALLOWED,
        content={
            "status_code": 405,
            "error": "Method Not Allowed",
            "detail": f"The HTTP {method} method is not supported for this endpoint.",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "path": path,
            "method": method,
            "allowed_methods": sorted(list(allowed_methods)),
            "hints": ["Use one of the allowed HTTP methods", "Check API documentation for correct method"]
        }
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """
    Handle 422 Unprocessable Entity validation errors
    
    LOGIC: 422 is correct for semantic validation errors (e.g., field constraints)
    vs 400 for malformed requests (e.g., invalid JSON syntax)
    
    Extract detailed error information for client debugging
    """
    errors = exc.errors()
    
    # Format errors in a user-friendly way
    formatted_errors = []
    for error in errors:
        field = ".".join(str(x) for x in error.get("loc", []))
        msg = error.get("msg", "Validation error")
        formatted_errors.append({
            "field": field,
            "error": msg,
            "type": error.get("type", "unknown")
        })
    
    logger.warning(f"[VALIDATION_ERROR] {request.method} {request.url.path} - {len(errors)} errors")
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "status_code": 422,
            "error": "Unprocessable Entity",
            "detail": "Request data validation failed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "path": str(request.url.path),
            "method": request.method,
            "errors": formatted_errors,
            "hints": ["Check field types and constraints", "Verify required fields are present", "Review API documentation"]
        }
    )

# TrustedHost middleware for additional security
# Only enable in production with proper domain
if not settings.DEBUG and os.getenv("ENABLE_TRUSTED_HOST", "false").lower() == "true":
    allowed_hosts = os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=allowed_hosts
    )

# CORS middleware - configured from settings to respect DEBUG/PRODUCTION modes
# ENHANCED: Multiple origin support with exact pattern matching
cors_origins = settings.CORS_ORIGINS

# Convert to list if single origin
if isinstance(cors_origins, str):
    cors_origins = [cors_origins]

# Clean up whitespace in origins
if isinstance(cors_origins, list) and len(cors_origins) > 0:
    cors_origins = [origin.strip() for origin in cors_origins if origin.strip()]

# SECURITY: Only add local development origins in debug mode
if settings.DEBUG:
    local_dev_origins = [
        "http://localhost:3000",
        "http://localhost:8000", 
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8000"
    ]
    
    # Merge origins without duplicates
    for origin in local_dev_origins:
        if origin not in cors_origins:
            cors_origins.append(origin)

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition", "X-Total-Count", "Access-Control-Allow-Origin", "Access-Control-Allow-Methods", "Access-Control-Allow-Headers", "Content-Length"],
    max_age=3600,  # Cache preflight requests for 1 hour
)

# CRITICAL FIX: Handle CORS preflight requests (OPTIONS) without requiring authentication
# Browser CORS preflight requests don't have auth headers, so they would fail 401 without this
# NOTE: FastAPI automatically handles OPTIONS for registered routes, this is fallback only
@app.options("/{full_path:path}")
async def handle_options_request(full_path: str, request: Request):
    """
    Handle CORS preflight OPTIONS requests.
    These must succeed without authentication for CORS to work in browsers.
    SECURITY: Use exact regex matching to prevent origin bypass attacks
    (e.g., https://evildomain.zaply.in.net would bypass substring matching)
    """
    import re
    origin = request.headers.get("Origin")
    
    # SECURITY LOGIC FIX: Validate origin with comprehensive patterns
    # AND operator: origin must match at least one allowed pattern
    allowed_origin = "null"  # Default: deny untrusted origins
    
    if origin:
        # SECURITY: Use exact whitelist matching to prevent subdomain bypass attacks
        # No regex patterns - exact string matching only
        allowed_origins = []
        
        # Production domains - exact matches only
        if not settings.DEBUG:
            allowed_origins.extend([
                "https://zaply.in.net",
                "https://www.zaply.in.net",
            ])
        
        # Development environments
        if settings.DEBUG:
            allowed_origins.extend([
                "http://zaply.in.net",
                "https://zaply.in.net",
                "http://localhost:3000",
                "https://localhost:3000",
                "http://localhost:8000",
                "https://localhost:8000",
                "http://127.0.0.1:3000",
                "https://127.0.0.1:3000",
                "http://127.0.0.1:8000", 
                "https://127.0.0.1:8000",
                "http://[::1]:3000",
                "https://[::1]:3000",
                "http://[::1]:8000",
                "https://[::1]:8000",
                # Docker environments
                "http://hypersend_frontend:3000",
                "http://hypersend_backend:8000",
                "http://frontend:3000",
                "http://backend:8000",
            ])
        
        # SECURITY: Exact match only - no pattern matching to prevent bypass
        allowed_origin = origin if origin in allowed_origins else None
    
    return Response(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": allowed_origin,
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH",
            "Access-Control-Allow-Headers": "Content-Type, Authorization, Accept, Origin, X-Requested-With",
            "Access-Control-Allow-Credentials": "true" if allowed_origin != "null" else "false",
            "Access-Control-Max-Age": "86400",
        }
    )

# Removed - consolidated into single health endpoint below

# Detailed status endpoint for debugging
@app.get("/api/v1/status")
async def api_status(request: Request):
    """
    Detailed API status endpoint for debugging connection issues.
    RESTRICTED: Only accessible in DEBUG mode or from localhost.
    """
    # Only allow access in debug mode or from localhost
    client_host = request.client.host if request.client else "unknown"
    
    if not settings.DEBUG and client_host not in ["127.0.0.1", "localhost", "::1"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This endpoint is only accessible in debug mode or from localhost"
        )
    
    # In production, return minimal information
    if not settings.DEBUG:
        return {
            "status": "operational",
            "service": "zaply-api",
            "version": "1.0.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    
    # In debug mode, return detailed information
    return {
        "status": "operational",
        "service": "zaply-api",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "api": {
            "base_url": settings.API_BASE_URL,
            "host": settings.API_HOST,
            "port": settings.API_PORT,
            "debug_mode": settings.DEBUG,
            "cors_origins": cors_origins[:3],  # Show first 3 origins only
        },
        "database": {
            "type": "MongoDB",
            "mock_mode": settings.USE_MOCK_DB,
        },
        "environment": "debug" if settings.DEBUG else "production",
    }

@app.get("/")
async def root():
    """Root endpoint - verify API is responding"""
    return {
        "app": "Hypersend",
        "version": "1.0.0",
        "status": "running",
        "environment": "debug" if settings.DEBUG else "production",
        "api_endpoint": settings.API_BASE_URL,
    }

# Security headers middleware
@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    
    # Add security headers (modified for HTTP-only deployment)
    security_headers = SecurityConfig.get_security_headers()
    
    # Remove HSTS if not using HTTPS
    if not request.url.scheme == "https":
        security_headers.pop("Strict-Transport-Security", None)
    
    for header, value in security_headers.items():
        response.headers[header] = value
    
    return response


# Serve favicon (avoid 404 in logs)
FAVICON_PATH = Path("frontend/assets/favicon.ico")

@app.get("/favicon.ico")
async def favicon():
    if FAVICON_PATH.exists():
        return FileResponse(str(FAVICON_PATH))
    return Response(status_code=204)


# Health check endpoint
@app.get("/health", tags=["System"])
@app.get("/api/v1/health", tags=["System"])
async def health_check():
    """Health check endpoint for monitoring and load balancers - multiple routes for compatibility"""
    try:
        # Check database connection
        try:
            from database import client
            if client:
                await client.admin.command('ping')
                db_status = "healthy"
            else:
                db_status = "not_connected"
        except Exception as db_error:
            db_status = f"error: {str(db_error)[:50]}"
        
        return {
            "status": "healthy",
            "service": "hypersend-api",
            "version": "1.0.0",
            "database": db_status,
            "cors_origins": cors_origins,
            "websocket_support": True,
            "p2p_relay": "enabled",
            "max_file_size_gb": settings.MAX_FILE_SIZE_BYTES / (1024**3),
            "chunk_size_mb": settings.CHUNK_SIZE / (1024**2),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error(f"[HEALTH_CHECK] Error: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "degraded",
                "service": "hypersend-api",
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        )


app.include_router(auth.router, prefix="/api/v1")
app.include_router(users.router, prefix="/api/v1")
app.include_router(chats.router, prefix="/api/v1")
app.include_router(groups.router, prefix="/api/v1")
app.include_router(messages.router, prefix="/api/v1")
app.include_router(files.router, prefix="/api/v1")
app.include_router(updates.router, prefix="/api/v1")
app.include_router(p2p_transfer.router, prefix="/api/v1")
app.include_router(channels.router, prefix="/api/v1")

# Add endpoint aliases for frontend compatibility
# Import models for alias endpoints
from models import UserLogin, UserCreate, Token, RefreshTokenRequest, UserResponse
from auth.utils import get_current_user

# Unified OPTIONS handler for all alias endpoints
@app.options("/api/v1/login")
@app.options("/api/v1/register") 
@app.options("/api/v1/refresh")
@app.options("/api/v1/logout")
async def preflight_alias_endpoints(request: Request):
    """Handle CORS preflight for alias endpoints"""
    import re
    origin = request.headers.get("Origin", "null")
    
    # SECURITY LOGIC FIX: Same comprehensive validation as main OPTIONS handler
    allowed_origin = "null"
    
    if origin and origin != "null":
        # LOGIC: Consistent with handle_options_request patterns
        allowed_patterns = [
            # Production HTTPS (critical for security)
            r'^https://([a-zA-Z0-9-]+\.)?zaply\.in\.net(:[0-9]+)?$',
            # Production HTTP (fallback - only in debug)
            r'^http://zaply\.in\.net(:[0-9]+)?$' if settings.DEBUG else None,
            # Development localhost (all ports and protocols)
            r'^https?://localhost(:[0-9]+)?$',
            r'^https?://127\.0\.0\.1(:[0-9]+)?$',
            r'^https?://\[::1\](:[0-9]+)?$',  # IPv6 loopback
            # Docker container names (HTTP only)
            r'^http://hypersend_frontend(:[0-9]+)?$',
            r'^http://hypersend_backend(:[0-9]+)?$',
            # Docker service names (HTTP only)
            r'^http://frontend(:[0-9]+)?$',
            r'^http://backend(:[0-9]+)?$',
        ]
        
        # Filter out None patterns (production mode removes HTTP for main domain)
        allowed_patterns = [p for p in allowed_patterns if p]
        
        # LOGIC: Check if origin matches any allowed pattern
        for pattern in allowed_patterns:
            if re.match(pattern, origin):
                allowed_origin = origin
                break
    
    return Response(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": allowed_origin,
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization, Accept, Origin, X-Requested-With",
            "Access-Control-Allow-Credentials": "true" if allowed_origin != "null" else "false",
            "Access-Control-Max-Age": "86400",
        }
    )

# Create redirect aliases - forward to auth handlers
@app.post("/api/v1/login", response_model=Token)
async def login_alias(credentials: UserLogin, request: Request):
    """Alias for /api/v1/auth/login - delegates to auth router"""
    from routes.auth import login as auth_login
    return await auth_login(credentials, request)

@app.post("/api/v1/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register_alias(user: UserCreate):
    """Alias for /api/v1/auth/register - delegates to auth router"""
    from routes.auth import register as auth_register
    return await auth_register(user)

@app.post("/api/v1/refresh", response_model=Token)
async def refresh_alias(refresh_request: RefreshTokenRequest):
    """Alias for /api/v1/auth/refresh - delegates to auth router"""
    from routes.auth import refresh_token as auth_refresh
    return await auth_refresh(refresh_request)

@app.post("/api/v1/logout")
async def logout_alias(current_user: str = Depends(get_current_user)):
    """Alias for /api/v1/auth/logout - delegates to auth router"""
    from routes.auth import logout as auth_logout
    return await auth_logout(current_user)

# Include debug routes (only in DEBUG mode, but router checks internally)
if settings.DEBUG:
    app.include_router(debug.router, prefix="/api/v1")
    print("[STARTUP] + Debug routes registered")




if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.DEBUG
    )
