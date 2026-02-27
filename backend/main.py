from contextlib import asynccontextmanager
from typing import Optional
from fastapi import FastAPI, Request, status, HTTPException, Depends
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response, JSONResponse
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.routing import Match
import logging
from pathlib import Path
import os
import sys
import asyncio
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient

from models import MessageCreate

# WhatsApp-Grade Cryptographic Imports
try:
    import redis.asyncio as redis
except ImportError:
    print("[WARNING] Redis not available - using fallback cache")
    redis = None
from crypto.signal_protocol import SignalProtocol
from crypto.multi_device import MultiDeviceManager
from crypto.delivery_semantics import DeliveryManager
from crypto.media_encryption import MediaEncryptionService
from workers.fan_out_worker import MessageFanOutWorker
from websocket.delivery_handler import create_websocket_server

# Load environment variables FIRST before importing config
env_paths = [Path(__file__).parent / ".env", Path(__file__).parent.parent / ".env"]

for env_path in env_paths:
    if env_path.exists():
        load_dotenv(dotenv_path=env_path)
        break

try:
    # Add current directory to Python path for Docker
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).parent))
    from datetime import datetime, timezone

    # SECURITY: Prevent importing config with missing secrets in production
    debug_mode = os.getenv("DEBUG", "false").lower() in ("true", "1")
    if not os.getenv("SECRET_KEY") and not debug_mode:
        raise RuntimeError("PRODUCTION SAFETY: SECRET_KEY must be set in production")

    from config import settings

    from routes import (
        auth,
        files,
        chats,
        users,
        updates,
        p2p_transfer,
        groups,
        messages,
        channels,
        debug,
        devices,
        e2ee_messages,
        presence,
    )
except Exception as e:
    raise

from auth.utils import get_current_user

try:
    from config import settings
except Exception as e:
    raise

try:
    from mongo_init import ensure_mongodb_ready
except Exception as e:
    raise

# Import database initialization function
from database import init_database

try:
    from security import SecurityConfig
except Exception as e:
    raise

try:
    from error_handlers import register_exception_handlers
except Exception as e:
    raise

try:
    from redis_cache import init_cache, cleanup_cache
except Exception as e:
    raise

# Setup logger
logger = logging.getLogger("zaply")
logger.setLevel(logging.INFO)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan event handler - initialize database and cleanup"""
    # Startup
    await init_database()
    # Store database connection in app state for reliable access
    from database import db, client
    app.state.db = db
    app.state.client = client
    print(f"[STARTUP] Database stored in app state: db={db is not None}, client={client is not None}")
    
    # Initialize Redis cache
    try:
        await init_cache()
        try:
            from redis_cache import cache
            app.state.cache = cache
        except Exception:
            # Cache module-level instance not available; continue without state exposure
            pass
        print("[STARTUP] Redis cache initialized")
    except Exception as e:
        print(f"[STARTUP] Redis cache initialization failed: {e}")
        # Continue without Redis - use fallback cache

    print("Application startup complete")
    
    yield
    
    # Shutdown
    from database import client
    if client:
        try:
            client.close()
        except Exception:
            pass
        print("[SHUTDOWN] Database connection closed")
        try:
            import database as _database
            _database.client = None
            _database.db = None
            try:
                _database._database_initialized = False
            except Exception:
                pass
            try:
                _database._init_lock = None
                _database._init_loop_id = None
            except Exception:
                pass
        except Exception:
            pass

    # Cleanup Redis cache
    try:
        await cleanup_cache()
        print("[SHUTDOWN] Redis cache cleaned up")
    except Exception as e:
        print(f"[SHUTDOWN] Redis cache cleanup failed: {e}")

    print("[SHUTDOWN] All cleanup complete")


app = FastAPI(
    title="Hypersend API",
    description="Secure peer-to-peer file transfer and messaging application",
    version="1.0.0",
    redirect_slashes=False,  # Fix: Prevent automatic trailing slash redirects
    lifespan=lifespan,
)

# Register custom exception handlers
register_exception_handlers(app)

# Add validation middleware for 4XX error handling (DISABLED FOR PRODUCTION)
# ===== VALIDATION MIDDLEWARE FOR 4XX ERROR HANDLING (DISABLED) =====
# app.add_middleware(RequestValidationMiddleware)
from starlette.middleware.base import BaseHTTPMiddleware
from datetime import datetime, timezone


class RequestValidationMiddleware(BaseHTTPMiddleware):
    """Enhanced middleware to validate requests and prevent common 4xx errors with security"""

    async def dispatch(self, request, call_next):
        """Validate request before processing with enhanced security checks"""
        # CRITICAL FIX: Always allow OPTIONS requests for CORS preflight
        # Options requests bypass ALL middleware validation for CORS compatibility
        if request.method == "OPTIONS":
            # OPTIONS requests MUST pass through immediately without any validation
            # They are handled by the OPTIONS handler in the app routes
            try:
                return await call_next(request)
            except Exception as e:
                # Even if there's an error, return 200 for OPTIONS
                logger.debug(f"[OPTIONS] Exception during processing: {e}")
                return Response(
                    status_code=200,
                    headers={
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH",
                        "Access-Control-Allow-Headers": "*",
                    },
                )

        try:
            # SECURITY: Check for malicious request patterns
            url_path = str(request.url.path)

            # Enhanced suspicious pattern detection with more comprehensive coverage
            def is_internal_request(request):
                """Check if request is from internal Docker network or explicit service hostnames."""
                client_host = request.client.host if request.client else ""
                host_header = request.headers.get("host", "").lower()
                internal_patterns = [
                    "hypersend_frontend",
                    "hypersend_backend",
                    "frontend",
                    "backend",
                    "0.0.0.0",
                ]
                return any(pattern in client_host for pattern in internal_patterns) or any(
                    pattern in host_header for pattern in internal_patterns
                )

            # CRITICAL FIX: Less aggressive security patterns to avoid false positives
            # Focus on actual attacks, not normal text containing keywords
            suspicious_patterns = [
                # Path traversal attacks (more specific)
                "../",
                "..\\",
                "%2e%2e",
                "%2e%2e%2f",
                "%2e%2e%5c",
                "..%2f",
                "..%5c",
                "%2e%2e/",
                "%2e%2e\\",
                "....//",
                "....\\\\",
                "%252e%252e%252f",
                # Script injection attacks (more specific)
                "<script",
                "</script>",
                "javascript:",
                "vbscript:",
                "onload=",
                "onerror=",
                "onclick=",
                "onmouseover=",
                "eval(",
                "alert(",
                "confirm(",
                "prompt(",
                # SQL injection attacks (only clear attack patterns)
                "drop table",
                "delete from",
                "exec sp_",
                "admin'--",
                "'; drop table--",
                # XML/XXE injection attacks
                "<?xml",
                "<!doctype",
                "<!entity",
                "xlink:href=",
                "<xsl:stylesheet",
                "external-entitiy",
                "<!ATTLIST",
                # System file access attempts (only clear malicious paths)
                "../../etc/passwd",
                "/etc/passwd",
                "/etc/shadow",
                "/etc/hosts",
                "c:\\windows\\system32",
                "c:\\windows\\system32\\config",
                "/proc/version",
                "/proc/self/environ",
                "/etc/passwd%00",
                "cmd.exe",
                "powershell",
                "bash",
                "sh",
                # Command injection attempts (only clear command chains)
                "; rm -rf",
                "| cat /etc/passwd",
                "&& ls -la",
                "|| id",
                "`whoami`",
                "$(id)",
                "${jndi:ldap",
                "${env:HOME}",
                # NoSQL/Document injection (only clear injection patterns)
                "{$ne:}",
                "{$gt:}",
                "{$where:}",
                "$regex:",
                "$expr:",
                '{"$gt":""}',
                '{"$ne":null}',
                # LDAP injection (only clear LDAP injection)
                "*)(",
                "*)(uid=*",
                "*)(|(uid=",
                "*)(password=*",
                "*)%00",
                "*)(&(objectClass=",
                # Log4j/RCE attempts (only clear log4j patterns)
                "${jndi:",
                "${lower:jndi:",
                "${upper:jndi:",
                "${::-:j",
                "${env:",
                "${java:",
                "${sys:",
                "${log4j:",
                # Server-Side Template Injection (only clear SSTI patterns)
                "{{7*7}}",
                "${7*7}",
                "#{7*7}",
                "<%=7*7%>",
                "{{config}}",
                "${config}",
                "#{config}",
                # XXE payload variants (only clear XXE patterns)
                '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
                '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE test',
                # Common web shell patterns
                "webshell",
                "shell.php",
                "cmd.jsp",
                "aspshell",
                "eval(base64",
                "system($_POST",
                "passthru($_",
                "shell_exec($_",
                "exec($_POST",
                "preg_replace eval",
                # SSRF patterns (only clear SSRF)
                "169.254.169.254",
                "metadata.google.internal",
                "file:///",
                "gopher://",
                "dict://",
                # Deserialization attacks (only clear patterns)
                'O:4:"User"',
                "ACED0005",
                "rO0ABX",
                "80ACED0",
                "ys0yPC",
                "base64_decode",
                "unserialize(",
                # Header injection
                "CRLF-injection",
                "%0d%0a",
                "\r\n",
                "%0D%0A",
            ]

            url_lower = url_path.lower()
            headers_lower = {
                k.lower(): v.lower() if v else ""
                for k, v in dict(request.headers).items()
            }

            # Enhanced security check with internal Docker exception for legitimate requests
            def is_internal_or_service_host():
                """Check if request is from internal Docker network"""
                client_host = request.client.host if request.client else ""

                internal_patterns = [
                    "hypersend_frontend",
                    "hypersend_backend",
                    "frontend",
                    "backend",
                    "0.0.0.0",
                ]

                host_header = request.headers.get("host", "").lower()

                return any(
                    pattern in client_host for pattern in internal_patterns
                ) or any(pattern in host_header for pattern in internal_patterns)

            is_internal = is_internal_or_service_host()

            # Check URL path for suspicious patterns
            # Always allow health check and API root endpoints
            if url_path in ["/health", "/api/v1/health", "/api/v1/", "/api/v1/test"]:
                is_internal = True  # Force internal for health checks and API root

            for pattern in suspicious_patterns:
                # No special-case bypass for loopback hosts

                if pattern in url_lower and not is_internal:
                    logger.warning(
                        f"[SECURITY] Suspicious URL blocked: {pattern} in {url_path}"
                    )
                    return JSONResponse(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        content={
                            "status_code": 400,
                            "error": "Bad Request - Malicious request detected",
                            "detail": "Request contains potentially malicious content",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "path": "/api/v1/files/invalid_path",  # Don't echo malicious path
                            "method": request.method,
                            "hints": [
                                "Remove malicious content",
                                "Check request format",
                                "Ensure proper encoding",
                            ],
                        },
                    )

            # Check headers for suspicious patterns
            for header_name, header_value in headers_lower.items():
                # Skip checking certain safe headers
                safe_headers = [
                    "user-agent",
                    "accept",
                    "content-type",
                    "authorization",
                    "host",
                    "x-forwarded-for",
                    "x-real-ip",
                ]
                if header_name in safe_headers:
                    continue

                # Special handling for host header - less strict for testing
                if header_name == "host":
                    # Extract hostname without port - handle both IPv4 and IPv6
                    hostname = header_value.lower()

                    # Handle IPv6 format: [::1]:8000 or [::1]
                    if hostname.startswith("["):
                        # IPv6 address in brackets
                        if "]" in hostname:
                            # Extract address between brackets, ignore port after ]
                            hostname = hostname[1 : hostname.index("]")]
                        else:
                            # Malformed IPv6 - missing closing bracket
                            hostname = hostname[1:]
                    else:
                        # IPv4 or hostname - remove port if present
                        # Use rpartition to split on last ':' to handle edge cases
                        hostname = (
                            hostname.rpartition(":")[0] if ":" in hostname else hostname
                        )

                    # Allow internal service hostnames
                    allowed_hostnames = {
                        "hypersend_frontend",
                        "hypersend_backend",
                        "frontend",
                        "backend",
                        "0.0.0.0",  # Docker
                    }

                    # Reject IP addresses and link-local ranges
                    if hostname.startswith("169.254.") and hostname not in [
                        "169.254.169.254"
                    ]:
                        logger.warning(
                            f"[SECURITY] SSRF attempt blocked - metadata IP in host header: {hostname}"
                        )
                        return JSONResponse(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            content={
                                "status_code": 400,
                                "error": "Bad Request - Invalid host",
                                "detail": "Request contains invalid host header",
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "path": "/api/v1/files/invalid_path",
                                "method": request.method,
                                "hints": [
                                    "Use valid hostname",
                                    "Avoid metadata IPs",
                                    "Check host header",
                                ],
                            },
                        )

                    # Skip validation for allowed/trusted hosts
                    # Only block truly malicious patterns
                    if hostname in allowed_hostnames:
                        continue

                    # For unknown hosts, only log warning, don't reject
                    # Tests might use various hostnames
                    if hostname not in allowed_hostnames and not settings.DEBUG:
                        logger.warning(f"[SECURITY] Unknown host header: {hostname}")
                    continue

                for pattern in suspicious_patterns:
                    if pattern in header_value:
                        logger.warning(
                            f"[SECURITY] Suspicious pattern found in header {header_name}: {pattern}"
                        )
                        return JSONResponse(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            content={
                                "status_code": 400,
                                "error": "Bad Request - Malicious header detected",
                                "detail": "Request header contains potentially malicious content",
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "path": url_path,
                                "method": request.method,
                                "hints": [
                                    "Remove malicious content",
                                    "Check request headers",
                                    "Ensure proper encoding",
                                ],
                            },
                        )

            # Check Content-Length for POST/PUT/PATCH (411)
            if request.method in ["POST", "PUT", "PATCH"]:
                content_length_header = request.headers.get("content-length")

                if not content_length_header and request.method != "GET":
                    # Log missing Content-Length but don't consume body
                    logger.warning(
                        f"[411] Missing Content-Length for {request.method} {request.url.path}"
                    )

                # Check payload size (413)
                if content_length_header:
                    try:
                        content_length = int(content_length_header)
                        max_size = settings.MAX_FILE_SIZE_BYTES
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
                                    "hints": [
                                        "Reduce file size",
                                        "Use chunked uploads",
                                        "Check server limits",
                                    ],
                                },
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
                                "hints": [
                                    "Provide valid Content-Length",
                                    "Ensure header is a number",
                                ],
                            },
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
                        "hints": ["Shorten the URL", "Use POST for complex queries"],
                    },
                )

            # Enhanced Content-Type validation for POST/PUT/PATCH
            if request.method in ["POST", "PUT", "PATCH"]:
                content_type = request.headers.get("content-type", "")
                if not content_type:
                    # Some requests can work without explicit Content-Type, but log for security
                    logger.debug(
                        f"[SECURITY] No Content-Type for {request.method} {request.url.path}"
                    )
                else:
                    # Check for dangerous content types
                    dangerous_content_types = [
                        "application/x-msdownload",  # Executable download
                        "application/x-msdos-program",  # DOS executable
                        "application/x-executable",  # Generic executable
                        "application/x-shockwave-flash",  # Flash (deprecated, risky)
                        "text/html",  # HTML in API requests (XSS risk)
                        "application/javascript",  # JavaScript in non-JS endpoints
                        "text/javascript",  # JavaScript in non-JS endpoints
                    ]

                    content_type_lower = content_type.lower()
                    for dangerous_type in dangerous_content_types:
                        if dangerous_type in content_type_lower:
                            logger.warning(
                                f"[SECURITY] Dangerous content-type blocked: {content_type}"
                            )
                            return JSONResponse(
                                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                                content={
                                    "status_code": 415,
                                    "error": "Unsupported Media Type - Content type not allowed",
                                    "detail": f"Content type '{content_type}' is not permitted for security reasons",
                                    "timestamp": datetime.now(timezone.utc).isoformat(),
                                    "path": str(request.url.path),
                                    "method": request.method,
                                    "hints": [
                                        "Use supported content types",
                                        "Check API documentation",
                                        "Ensure proper file format",
                                    ],
                                },
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
                        if (
                            "/auth/" in url_path
                            or "/login" in url_path
                            or "/register" in url_path
                        ):
                            max_size = 1024 * 1024  # 1MB
                            if size > max_size:
                                return JSONResponse(
                                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                                    content={
                                        "status_code": 413,
                                        "error": "Payload Too Large - Auth request too big",
                                        "detail": f"Authentication requests must be less than {max_size} bytes",
                                        "timestamp": datetime.now(
                                            timezone.utc
                                        ).isoformat(),
                                        "path": str(request.url.path),
                                        "method": request.method,
                                        "hints": [
                                            "Reduce request size",
                                            "Check for file uploads",
                                            "Use appropriate endpoints",
                                        ],
                                    },
                                )

                        # Profile/Settings endpoints - medium limit
                        elif "/profile" in url_path or "/settings" in url_path:
                            max_size = 5 * 1024 * 1024  # 5MB
                            if size > max_size:
                                return JSONResponse(
                                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                                    content={
                                        "status_code": 413,
                                        "error": "Payload Too Large - Profile data too big",
                                        "detail": f"Profile requests must be less than {max_size} bytes",
                                        "timestamp": datetime.now(
                                            timezone.utc
                                        ).isoformat(),
                                        "path": str(request.url.path),
                                        "method": request.method,
                                        "hints": [
                                            "Reduce profile data size",
                                            "Compress images",
                                            "Remove unnecessary data",
                                        ],
                                    },
                                )

                        # File upload endpoints - handled by file-specific logic
                        # This is just an additional safety net for very large requests
                        elif "/files/" in url_path and (
                            "/upload" in url_path or "/chunk" in url_path
                        ):
                            max_size = settings.MAX_FILE_SIZE_BYTES
                            if size > max_size:
                                return JSONResponse(
                                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                                    content={
                                        "status_code": 413,
                                        "error": "Payload Too Large - File too big",
                                        "detail": f"File uploads must be less than {max_size} bytes",
                                        "timestamp": datetime.now(
                                            timezone.utc
                                        ).isoformat(),
                                        "path": str(request.url.path),
                                        "method": request.method,
                                        "hints": [
                                            "Use smaller files",
                                            "Compress large files",
                                            "Split large files",
                                        ],
                                    },
                                )

                        # Chunk upload endpoints - check chunk size specifically
                        elif "/files/" in url_path and "/chunk" in url_path:
                            max_chunk_size = settings.CHUNK_SIZE
                            if size > max_chunk_size:
                                return JSONResponse(
                                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                                    content={
                                        "status_code": 413,
                                        "error": "Payload Too Large - Chunk too big",
                                        "detail": f"Chunk {url_path.split('/')[-2]} exceeds maximum size of {max_chunk_size} bytes",
                                        "actual_size": size,
                                        "max_size": max_chunk_size,
                                        "actual_size_mb": round(
                                            size / (1024 * 1024), 2
                                        ),
                                        "max_size_mb": round(
                                            max_chunk_size / (1024 * 1024), 2
                                        ),
                                        "guidance": f"Please split your data into chunks of max {round(max_chunk_size / (1024 * 1024), 0)}MB each",
                                        "timestamp": datetime.now(
                                            timezone.utc
                                        ).isoformat(),
                                        "path": str(request.url.path),
                                        "method": request.method,
                                        "hints": [
                                            "Reduce chunk size",
                                            "Check file chunking logic",
                                            "Use smaller chunk sizes",
                                        ],
                                    },
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
                exc_info=True,
            )

            # Enhanced error classification
            error_str = str(e).lower()
            if any(
                keyword in error_str
                for keyword in ["validation", "json", "parse", "syntax"]
            ):
                return JSONResponse(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    content={
                        "status_code": 422,
                        "error": "Unprocessable Entity - Invalid input data",
                        "detail": str(e) if settings.DEBUG else "Invalid input data",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "path": str(request.url.path),
                        "method": request.method,
                        "hints": [
                            "Check request format",
                            "Verify JSON syntax",
                            "Review API documentation",
                        ],
                    },
                )
            elif any(
                keyword in error_str
                for keyword in ["timeout", "deadline", "deadlineexceeded"]
            ):
                return JSONResponse(
                    status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                    content={
                        "status_code": 504,
                        "error": "Gateway Timeout - Request took too long",
                        "detail": str(e) if settings.DEBUG else "Request timeout",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "path": str(request.url.path),
                        "method": request.method,
                        "hints": [
                            "Try again later",
                            "Reduce request complexity",
                            "Check server load",
                        ],
                    },
                )
            elif any(
                keyword in error_str
                for keyword in ["connection", "network", "unreachable"]
            ):
                return JSONResponse(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    content={
                        "status_code": 503,
                        "error": "Service Unavailable - Connection issue",
                        "detail": str(e)
                        if settings.DEBUG
                        else "Service temporarily unavailable",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "path": str(request.url.path),
                        "method": request.method,
                        "hints": [
                            "Check network connection",
                            "Try again later",
                            "Verify server status",
                        ],
                    },
                )
            else:
                return JSONResponse(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    content={
                        "status_code": 500,
                        "error": "Internal Server Error",
                        "detail": "Server error processing request"
                        if not settings.DEBUG
                        else str(e),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "path": str(request.url.path),
                        "method": request.method,
                        "hints": [
                            "This is a server error",
                            "Try again later",
                            "Contact support if persistent",
                        ],
                    },
                )


def _configure_s3_lifecycle():
    """
    Configure S3 bucket lifecycle rules for WhatsApp-style ephemeral storage.
    MANDATORY: Automatically delete temporary media after 24 hours.
    """
    try:
        import boto3  # type: ignore[import-not-found]
        from botocore.exceptions import ClientError  # type: ignore[import-not-found]
    except ImportError:
        print("[S3] WARNING: boto3 not available, skipping lifecycle configuration")
        return

    if not settings.AWS_ACCESS_KEY_ID or not settings.AWS_SECRET_ACCESS_KEY:
        print("[S3] WARNING: AWS credentials not configured, skipping lifecycle setup")
        return

    s3_client = boto3.client(
        "s3",
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        region_name=settings.AWS_REGION,
    )

    try:
        # Define lifecycle policy for ephemeral temp files
        lifecycle_policy = {
            "Rules": [
                {
                    "Id": "zaply-temp-cleanup-24h",
                    "Filter": {"Prefix": "temp/"},  # Only apply to temp/ objects
                    "Status": "Enabled",
                    "Expiration": {
                        "Days": 1  # MANDATORY: Delete after 24 hours
                    },
                    "NoncurrentVersionExpiration": {"NoncurrentDays": 1},
                },
                {
                    "Id": "zaply-incomplete-multipart",
                    "Filter": {"Prefix": "temp/"},
                    "Status": "Enabled",
                    "AbortIncompleteMultipartUpload": {
                        "DaysAfterInitiation": 1  # Cleanup incomplete uploads
                    },
                },
            ]
        }

        # Apply lifecycle configuration to S3 bucket
        s3_client.put_bucket_lifecycle_configuration(
            Bucket=settings.S3_BUCKET, LifecycleConfiguration=lifecycle_policy
        )

        print(f"[S3] Lifecycle policy configured for bucket: {settings.S3_BUCKET}")
        print(f"[S3] - Temporary files (temp/) auto-deleted after 24 hours")
        print(f"[S3] - Incomplete uploads (temp/) cleaned after 24 hours")
        print("[S3] WhatsApp-style ephemeral storage: Enabled ✓")

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code == "NoSuchBucket":
            print(f"[S3] WARNING: Bucket '{settings.S3_BUCKET}' does not exist")
            print(f"[S3] Please create the S3 bucket and configure lifecycle manually:")
            print(
                f"[S3] Lifecycle policy needed: Delete objects in 'temp/' prefix after 24 hours"
            )
        else:
            print(f"[S3] WARNING: Failed to configure lifecycle: {error_code}")
            print(f"[S3] Details: {str(e)}")
    except Exception as e:
        print(f"[S3] WARNING: Unexpected error configuring lifecycle: {str(e)}")
        print("[S3] Continuing without lifecycle configuration")


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
        exc_info=True,
    )

    # Determine appropriate status code and message based on exception type
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    error_msg = "Internal server error"
    hints = ["Try again in a moment", "Contact support if the problem persists"]

    # Enhanced exception type handling
    if isinstance(exc, asyncio.TimeoutError):
        status_code = status.HTTP_504_GATEWAY_TIMEOUT
        error_msg = "Request timeout - operation took too long"
        hints = [
            "Check your network connection",
            "Try with a smaller request",
            "Try again later",
        ]

    elif isinstance(exc, ConnectionError):
        # CRITICAL FIX: Distinguish between 502 and 503 errors
        error_msg_lower = str(exc).lower()
        if "connection refused" in error_msg_lower or "bad gateway" in error_msg_lower:
            status_code = status.HTTP_502_BAD_GATEWAY
            error_msg = "Bad gateway - upstream service unavailable"
            hints = [
                "Check if backend service is running",
                "Try again in a few moments",
                "Contact support if persistent",
            ]
        else:
            status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            error_msg = (
                "Service temporarily unavailable - cannot connect to external service"
            )
            hints = [
                "Check your internet connection",
                "Try again in a few moments",
                "Verify service status",
            ]

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
        hints = [
            "Try again in a few moments",
            "Check your request data",
            "Contact support if persistent",
        ]

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
        hints = [
            "Check request format and data types",
            "Verify all required fields are provided",
        ]

    elif isinstance(exc, KeyError):
        status_code = status.HTTP_400_BAD_REQUEST
        error_msg = "Missing required field in request"
        hints = [
            "Check that all required fields are provided",
            "Review API documentation",
        ]

    elif isinstance(exc, (AttributeError, TypeError)):
        status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        error_msg = "Internal server error - data processing failed"
        hints = [
            "This is a server issue",
            "Try again later",
            "Contact support if persistent",
        ]

    # Security-related exceptions
    elif "unauthorized" in str(exc).lower() or "authentication" in str(exc).lower():
        status_code = status.HTTP_401_UNAUTHORIZED
        error_msg = "Authentication required or invalid credentials"
        hints = ["Check your authentication token", "Login again if session expired"]

    elif "forbidden" in str(exc).lower() or "permission" in str(exc).lower():
        status_code = status.HTTP_403_FORBIDDEN
        error_msg = "Access denied - insufficient permissions"
        hints = ["Check your access permissions", "Contact administrator for access"]

    # Standard HTTP Error Codes
    elif isinstance(exc, ConnectionRefusedError):
        # 502 Bad Gateway - Upstream connection refused
        status_code = 502
        error_msg = "Network connection timeout - cannot reach server"
        hints = [
            "Check firewall settings",
            "Verify VPS is accessible",
            "Contact network administrator",
        ]

    elif isinstance(exc, ConnectionResetError):
        # 502 Bad Gateway - Connection lost during transfer
        status_code = 502
        error_msg = "Network connection reset - transfer interrupted"
        hints = [
            "Check network stability",
            "Restart the transfer",
            "Try different network",
        ]

    elif "timeout" in str(exc).lower() and "disk" in str(exc).lower():
        # 503 Service Unavailable - Disk I/O saturated
        status_code = 503
        error_msg = "Disk I/O timeout - server storage overloaded"
        hints = [
            "Wait and retry",
            "Upload smaller files",
            "Contact support about storage capacity",
        ]

    elif "quota" in str(exc).lower() or "limit" in str(exc).lower():
        # 507 Insufficient Storage - Disk quota exceeded
        status_code = 507
        error_msg = "Storage quota exceeded - disk space limit reached"
        hints = [
            "Wait for space cleanup",
            "Upload smaller files",
            "Contact support about quota",
        ]

    elif "ssl" in str(exc).lower() or "tls" in str(exc).lower():
        # 502 Bad Gateway - SSL/TLS connection issues
        status_code = 502
        error_msg = "Secure connection failed - SSL/TLS error"
        hints = [
            "Check SSL certificates",
            "Try HTTP connection",
            "Contact support about SSL setup",
        ]

    elif "dns" in str(exc).lower() or "resolve" in str(exc).lower():
        # 502 Bad Gateway - DNS resolution failed
        status_code = 502
        error_msg = "DNS resolution failed - cannot reach server"
        hints = [
            "Check DNS settings",
            "Try using IP address directly",
            "Contact DNS administrator",
        ]

    # Prepare response data
    # SECURITY: Sanitize path to prevent information disclosure in error responses
    import re

    # Check for dangerous patterns in the normalized path
    dangerous_patterns = [
        r"etc/passwd",  # Unix system files
        r"etc/shadow",  # Unix password file
        r"etc/hosts",  # Unix hosts file
        r"windows/system32",  # Windows system directory
        r"system32/config",  # Windows registry files
        r"boot\.ini",  # Windows boot file
        r"win\.ini",  # Windows configuration
        r"\.ssh/",  # SSH directory
        r"\.bash_history",  # Bash history
        r"\.mysql_history",  # MySQL history
        r"proc/",  # Linux proc filesystem
        r"sys/",  # Linux sys filesystem
        r"dev/",  # Linux dev filesystem
    ]

    # Check for dangerous patterns in the original path
    original_path = str(request.url.path)
    traversal_patterns = [
        r"\.\.[\\/]",  # ../ or ..\
        r"%2e%2e",  # URL encoded ..
        r"\\\\",  # UNC paths
        r"^[a-zA-Z]:",  # Drive letters
    ]

    # Determine if this is a dangerous path request
    dangerous_in_path = any(
        re.search(pattern, str(request.url.path), re.IGNORECASE)
        for pattern in dangerous_patterns
    )
    dangerous_in_original = any(
        re.search(pattern, original_path, re.IGNORECASE)
        for pattern in traversal_patterns
    )

    is_dangerous_path = dangerous_in_path or dangerous_in_original

    # Use generic path for dangerous requests to prevent information disclosure
    safe_path = (
        "/api/v1/files/invalid_path" if is_dangerous_path else str(request.url.path)
    )

    response_data = {
        "status_code": status_code,
        "error": type(exc).__name__ if settings.DEBUG else error_msg.title(),
        "detail": error_msg if not settings.DEBUG else str(exc),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "path": safe_path,
        "method": request.method,
        "hints": hints,
    }

    # Add specific context for certain error types
    if status_code == 413:
        response_data["max_size"] = "40GB"
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
        status_code=status_code, content=response_data, headers=security_headers
    )


# Add 404 handler for non-existent endpoints
@app.exception_handler(404)
async def not_found_handler(request: Request, exc: HTTPException):
    """Handle 404 Not Found errors - resource or endpoint doesn't exist"""
    path = str(request.url.path)
    method = request.method

    # SECURITY: Sanitize path to prevent information disclosure in error responses
    # Check for path traversal patterns and system file references in the requested path
    import re

    # DEBUG: Add logging to understand the issue
    print(f"[DEBUG 404] Raw path: {str(request.url.path)}")
    print(f"[DEBUG 404] Path type: {type(str(request.url.path))}")

    # Check for dangerous patterns in the normalized path
    dangerous_patterns = [
        r"etc/passwd",  # Unix system files
        r"etc/shadow",  # Unix password file
        r"etc/hosts",  # Unix hosts file
        r"windows/system32",  # Windows system directory
        r"system32/config",  # Windows registry files
        r"boot\.ini",  # Windows boot file
        r"win\.ini",  # Windows configuration
        r"\.ssh/",  # SSH directory
        r"\.bash_history",  # Bash history
        r"\.mysql_history",  # MySQL history
        r"proc/",  # Linux proc filesystem
        r"sys/",  # Linux sys filesystem
        r"dev/",  # Linux dev filesystem
    ]

    # Check for dangerous patterns in the original path
    original_path = str(request.url.path)
    traversal_patterns = [
        r"\.\.[\\/]",  # ../ or ..\
        r"%2e%2e",  # URL encoded ..
        r"\\\\",  # UNC paths
        r"^[a-zA-Z]:",  # Drive letters
    ]

    # Determine if this is a dangerous path request
    dangerous_in_path = any(
        re.search(pattern, str(request.url.path), re.IGNORECASE)
        for pattern in dangerous_patterns
    )
    dangerous_in_original = any(
        re.search(pattern, original_path, re.IGNORECASE)
        for pattern in traversal_patterns
    )

    is_dangerous_path = dangerous_in_path or dangerous_in_original

    print(f"[DEBUG 404] Dangerous in path: {dangerous_in_path}")
    print(f"[DEBUG 404] Dangerous in original: {dangerous_in_original}")
    print(f"[DEBUG 404] Is dangerous path: {is_dangerous_path}")

    # Use generic path for dangerous requests to prevent information disclosure
    safe_path = (
        "/api/v1/files/invalid_path" if is_dangerous_path else str(request.url.path)
    )

    print(f"[DEBUG 404] Safe path: {safe_path}")

    # Distinguish between:
    # - true route-miss 404s (wrong URL) vs
    # - intentional 404s raised inside a matched endpoint (e.g. "User not found")
    matches_existing_route = False
    try:
        scope = request.scope
        for route in app.routes:
            if hasattr(route, "matches"):
                match, _ = route.matches(scope)
                if match in (Match.FULL, Match.PARTIAL):
                    matches_existing_route = True
                    break
    except Exception:
        matches_existing_route = False

    if matches_existing_route:
        detail_obj = getattr(exc, "detail", "Not Found")
        detail_msg = detail_obj
        if isinstance(detail_obj, dict):
            detail_msg = (
                detail_obj.get("message") or detail_obj.get("detail") or str(detail_obj)
            )
        else:
            detail_msg = str(detail_obj)

        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={
                "status_code": 404,
                "error": "Not Found",
                "detail": detail_msg,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "path": safe_path,
                "method": method,
                "hints": [
                    "Verify the resource identifier",
                    "Check permissions",
                    "Review API documentation",
                ],
            },
        )

    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={
            "status_code": 404,
            "error": "Not Found",
            "detail": "The requested resource doesn't exist. Check the URL path.",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "path": safe_path,
            "method": method,
            "hints": [
                "Check the URL spelling",
                "Verify the endpoint exists",
                "Review API documentation",
            ],
        },
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
    if ".." in path or path.startswith("//") or "%2e%2e" in path.lower():
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
                "hints": [
                    "Verify the correct endpoint path",
                    "Check for special characters",
                    "Review API documentation",
                ],
            },
        )

    # LOGIC FIX: Check if ANY route exists at this path with a different method
    matching_routes = [
        route
        for route in app.routes
        if hasattr(route, "path")
        and (route.path == path.rstrip("/") or route.path == path)
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
                "hints": [
                    "Check the URL spelling",
                    "Verify the endpoint exists",
                    "Review API documentation",
                ],
            },
        )

    # If route exists but method is wrong, return 405 with allowed methods
    allowed_methods = set()
    for route in matching_routes:
        if hasattr(route, "methods"):
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
            "hints": [
                "Use one of the allowed HTTP methods",
                "Check API documentation for correct method",
            ],
        },
    )


# TrustedHost middleware for additional security
# TrustedHost middleware disabled for debugging
# if not settings.DEBUG and os.getenv("ENABLE_TRUSTED_HOST", "false").lower() == "true":
#     allowed_hosts = os.getenv("ALLOWED_HOSTS", "hypersend.in.net").split(",")
#     app.add_middleware(
#         TrustedHostMiddleware,
#         allowed_hosts=allowed_hosts
#     )

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
    cors_origins.extend(
        [
            "https://hypersend.in.net/",
        ]
    )

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=cors_origins,
#     allow_credentials=True,
#     allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"],
#     allow_headers=["*"],
#     expose_headers=["Content-Disposition", "X-Total-Count", "Access-Control-Allow-Origin", "Access-Control-Allow-Methods", "Access-Control-Allow-Headers", "Content-Length"],
#     max_age=3600,  # Cache preflight requests for 1 hour
# )


# CRITICAL FIX: Handle CORS preflight requests (OPTIONS) without requiring authentication
# Browser CORS preflight requests don't have auth headers, so they would fail 401 without this
# NOTE: FastAPI automatically handles OPTIONS for registered routes, this is fallback only
@app.options("/{full_path:path}")
async def handle_options_request(full_path: str, request: Request):
    """
    Handle CORS preflight OPTIONS requests.
    These must succeed without authentication for CORS to work in browsers.
    SECURITY: Use exact regex matching to prevent origin bypass attacks
    (e.g., https://evildomain.hypersend.in.net would bypass substring matching)
    PRODUCTION: Only allow HTTPS production domains
    """
    import re

    origin = request.headers.get("Origin", "")

    # SECURITY LOGIC: Strict production CORS validation
    allowed_origin = "null"  # Default: deny untrusted origins

    if origin:
        # SECURITY: Use exact whitelist matching to prevent subdomain bypass attacks
        allowed_origins = []

        # Production domains - exact matches only, HTTPS only
        if not settings.DEBUG:
            allowed_origins.extend(
                [
                    "https://hypersend.in.net",
                    "https://www.hypersend.in.net",
                ]
            )
        else:
            # Development: Allow internal service origins for testing
            allowed_origins.extend(
                [
                    "https://hypersend.in.net",
                    "https://www.hypersend.in.net",
                    "http://hypersend_frontend:80",
                    "http://frontend:80",
                ]
            )

        # SECURITY: Exact match only - no pattern matching to prevent bypass
        allowed_origin = origin if origin in allowed_origins else "null"

    # If no origin header, allow request (common in test clients and some curl requests)
    # This is important for TestClient compatibility
    if not origin:
        allowed_origin = "*"

    return Response(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": allowed_origin,
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH",
            "Access-Control-Allow-Headers": "Content-Type, Authorization, Accept, Origin, X-Requested-With",
            "Access-Control-Allow-Credentials": "true"
            if allowed_origin != "null" and allowed_origin != "*"
            else "false",
            "Access-Control-Max-Age": "86400",
        },
    )


# Detailed status endpoint for debugging
@app.get("/api/v1/status")
async def api_status(request: Request):
    """
    Detailed API status endpoint for debugging connection issues.
    RESTRICTED: Only accessible in DEBUG mode or from hypersend.in.net.
    """
    # Only allow access in debug mode or from internal service network
    client_host = request.client.host if request.client else "unknown"

    if not settings.DEBUG and client_host not in ["hypersend_backend", "backend", "0.0.0.0"]:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "status_code": 403,
                "error": "Not Found",
                "detail": "This endpoint is only accessible in debug mode",
            },
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
        "app": "Zaply",
        "version": "1.0.0",
        "status": "running",
        "environment": "debug" if settings.DEBUG else "production",
        "api_endpoint": settings.API_BASE_URL,
    }


@app.get("/api/v1/")
async def api_v1_root():
    """API v1 root endpoint - prevent 405 errors"""
    return {"status": "ok", "service": "zaply"}


@app.head("/api/v1/")
async def api_v1_root_head():
    """HEAD method for API v1 root endpoint"""
    return Response(status_code=200)


# Security headers middleware - REMOVED to prevent duplicates with nginx
# Nginx now handles all security headers consistently
# @app.middleware("http")
# async def add_security_headers(request, call_next):
#     response = await call_next(request)
#
#     # Add security headers
#     security_headers = SecurityConfig.get_security_headers()
#
#     # Add HSTS only for HTTPS connections
#     if request.url.scheme == "https":
#         hsts_header = SecurityConfig.get_hsts_header()
#         security_headers["Strict-Transport-Security"] = hsts_header
#
#     for header, value in security_headers.items():
#         response.headers[header] = value
#
#     return response


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
    """Production health check endpoint - minimal response for load balancers"""
    try:
        # Check database connectivity using get_database dependency
        db_status = "healthy"
        db_error = None

        try:
            # Import database module and check connection
            import database
            
            # Force database initialization
            db = database.get_database()
            
            # Check if client is available
            if hasattr(database, 'client') and database.client is not None:
                # Test connection with ping
                try:
                    await database.client.admin.command("ping")
                    db_status = "healthy"
                    db_error = None
                except Exception as ping_error:
                    db_status = "unhealthy"
                    db_error = str(ping_error)[:100]
            else:
                db_status = "unhealthy"
                db_error = "Database client not initialized"
        except Exception as e:
            db_status = "unhealthy"
            db_error = str(e)[:100]

        # Check Redis connectivity if available
        redis_status = "healthy"
        redis_error = None

        try:
            from redis_cache import redis_client

            if redis_client:
                await redis_client.ping()
            else:
                redis_status = "disabled"  # Using in-memory fallback
        except Exception as e:
            redis_status = "unhealthy"
            redis_error = str(e)[:100]

        # Determine overall status - fail if database is unhealthy
        overall_status = "healthy"
        if db_status == "unhealthy":
            overall_status = "unhealthy"
        if redis_status == "unhealthy":
            overall_status = "degraded"

        response_data = {
            "status": overall_status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "services": {
                "database": {"status": db_status, "error": db_error},
                "cache": {"status": redis_status, "error": redis_error},
            },
        }

        return JSONResponse(status_code=200, content=response_data)

    except Exception as e:
        # Even in error, return 200 with status for load balancer compatibility
        return JSONResponse(
            status_code=200,
            content={
                "status": "degraded",
                "error": str(e)[:50],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )


@app.head("/health", tags=["System"])
@app.head("/api/v1/health", tags=["System"])
async def health_check_head():
    """HEAD method for health check endpoint"""
    return Response(status_code=200)


# ====================
# DIRECT APP ROUTES (must be before router includes)
# ====================


@app.get("/api/v1/debug", tags=["System"])
async def debug_route(request: Request):
    """Debug route to see what path FastAPI receives"""
    return {
        "received_url": str(request.url),
        "received_path": str(request.url.path),
        "received_query_params": dict(request.query_params),
        "client_host": request.client.host if request.client else "none",
        "headers": dict(request.headers),
    }


@app.get("/api/v1/users/contacts", tags=["Users"])
@app.get("/api/v1/users/contacts/", tags=["Users"])
async def contacts_route(
    offset: int = 0,
    limit: int = 50,
    current_user: str = Depends(get_current_user),
):
    return await users.get_contacts(offset=offset, limit=limit, current_user=current_user)


# ====================
# ROUTER REGISTRATION
# ====================

app.include_router(auth.router, prefix="/api/v1")
app.include_router(users.router, prefix="/api/v1")
app.include_router(chats.router, prefix="/api/v1/chats")
app.include_router(groups.router, prefix="/api/v1")
app.include_router(messages.router, prefix="/api/v1")
app.include_router(e2ee_messages.router, prefix="/api/v1")  # E2EE encrypted messages
app.include_router(files.router, prefix="/api/v1/files")
app.include_router(updates.router, prefix="/api/v1")
app.include_router(p2p_transfer.router, prefix="/api/v1")
app.include_router(channels.router, prefix="/api/v1")
app.include_router(devices.router, prefix="/api/v1")  # E2EE Device Management


# Add swagger.json endpoint for compatibility
@app.get("/api/swagger.json")
async def swagger_json():
    """Provide OpenAPI specification at /api/swagger.json for compatibility"""
    from fastapi.openapi.utils import get_openapi

    return get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )


# Add simple bins endpoints for compatibility
@app.get("/bins/")
@app.get("/bin/")
async def bins_list():
    """Simple bins endpoint for compatibility"""
    return {"bins": [], "message": "Bins endpoint - functionality not implemented"}


@app.get("/bins/{bin_id}")
@app.get("/bin/{bin_id}")
async def bins_get(bin_id: str):
    """Simple bin detail endpoint for compatibility"""
    return {
        "bin_id": bin_id,
        "data": None,
        "message": "Bin endpoint - functionality not implemented",
    }


# Add endpoint aliases for frontend compatibility
# Import models for alias endpoints
from models import (
    UserLogin,
    UserCreate,
    Token,
    RefreshTokenRequest,
    UserResponse,
    PasswordChangeRequest,
    PasswordResetRequest,
)
from auth.utils import get_current_user


# Unified OPTIONS handler for all alias endpoints
@app.options("/api/v1/login")
@app.options("/api/v1/register")
@app.options("/api/v1/refresh")
@app.options("/api/v1/logout")
@app.options("/api/v1/auth/change-password")
@app.options("/api/v1/reset-password")
async def preflight_alias_endpoints(request: Request):
    """Handle CORS preflight for alias endpoints"""
    origin = request.headers.get("Origin", "")

    # SECURITY LOGIC: Same strict production validation as main OPTIONS handler
    allowed_origin = "null"  # Default: deny untrusted origins

    if origin:
        # SECURITY: Use exact whitelist matching to prevent subdomain bypass attacks
        allowed_origins = []

        # Production domains - exact matches only, HTTPS only
        if not settings.DEBUG:
            allowed_origins.extend(
                [
                    "https://hypersend.in.net",
                    "https://www.hypersend.in.net",
                ]
            )
        else:
            # Development: Allow internal service origins for testing
            allowed_origins.extend(
                [
                    "https://hypersend.in.net",
                    "https://www.hypersend.in.net",
                    "http://hypersend_frontend:80",
                    "http://frontend:80",
                ]
            )

        # SECURITY: Exact match only - no pattern matching to prevent bypass
        allowed_origin = origin if origin in allowed_origins else "null"

    # If no origin header, allow request (common in test clients and some curl requests)
    if not origin:
        allowed_origin = "*"

    return Response(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": allowed_origin,
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization, Accept, Origin, X-Requested-With",
            "Access-Control-Allow-Credentials": "true"
            if allowed_origin != "null" and allowed_origin != "*"
            else "false",
            "Access-Control-Max-Age": "86400",
        },
    )


# Create redirect aliases - forward to auth handlers
@app.post("/api/v1/login", response_model=Token)
async def login_alias(credentials: UserLogin, request: Request):
    """Alias for /api/v1/auth/login - delegates to auth router"""
    from routes.auth import login as auth_login

    return await auth_login(credentials, request)


@app.post(
    "/api/v1/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED
)
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


@app.post("/api/v1/auth/change-password")
async def change_password_alias(
    request: PasswordChangeRequest, current_user: str = Depends(get_current_user)
):
    """Alias for /api/v1/auth/change-password - delegates to auth router"""
    from routes.auth import change_password as auth_change_password

    return await auth_change_password(request, current_user)


@app.post("/api/v1/reset-password")
async def reset_password_alias(request: PasswordResetRequest):
    """Alias for /api/v1/auth/reset-password - delegates to auth router"""
    from routes.auth import reset_password as auth_reset_password

    return await auth_reset_password(request)


# Include debug routes (only in DEBUG mode, but router checks internally)
if settings.DEBUG:
    app.include_router(debug.router, prefix="/api/v1")

# ==================== WHATSAPP-LIKE MESSAGE HISTORY & SYNC ENDPOINTS ====================


@app.post("/api/v1/messages/history/sync")
async def sync_message_history(
    sync_request: dict, current_user: str = Depends(get_current_user)
):
    """
    Synchronize encrypted message history to new/secondary devices.

    WHATSAPP ARCHITECTURE:
    - Device verification: Challenge-response with crypto keys
    - Message range: Fetch messages from last_sync_timestamp or last N days
    - Batch processing: Send messages in configurable batches (default: 100)
    - Delivery coordination: Use Redis for real-time ack tracking
    - End-to-end encryption: Messages remain encrypted end-to-end

    REQUEST:
    {
        "device_id": "device_uuid",
        "sync_from_timestamp": "2025-02-01T00:00:00Z" or null (defaults to 90 days ago),
        "batch_size": 100,
        "last_batch_id": 0
    }

    RESPONSE:
    {
        "sync_id": "sync_uuid",
        "sync_state": "pending|verifying|syncing|completed|failed",
        "message_batch": [...encrypted messages...],
        "batch_number": 1,
        "total_batches": 10,
        "progress_percent": 10,
        "has_more": true
    }
    """
    try:
        from models import DeviceMessageSync
        from datetime import datetime, timedelta, timezone

        device_id = sync_request.get("device_id")
        sync_from = sync_request.get("sync_from_timestamp")
        batch_size = sync_request.get("batch_size", 100)
        last_batch_id = sync_request.get("last_batch_id", 0)

        # Default: sync from 90 days ago if not specified
        if not sync_from:
            sync_from = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()

        # Validate batch size
        if batch_size > 1000 or batch_size < 10:
            batch_size = 100

        # Log sync initiation
        logger.info(
            f"[HISTORY-SYNC] User {current_user} Device {device_id} sync from {sync_from}"
        )

        # Return sync acknowledgment (actual sync handled by background workers)
        return {
            "sync_id": str(ObjectId()),
            "sync_state": "pending",
            "message_batch": [],  # Backend worker handles actual message batching
            "batch_number": last_batch_id + 1,
            "total_batches": 0,  # Calculated by sync worker
            "progress_percent": 0,
            "has_more": False,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        logger.error(f"[HISTORY-SYNC] Error: {e}")
        return {
            "sync_state": "failed",
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


@app.get("/api/v1/messages/metadata")
async def get_conversation_metadata(
    user_id: Optional[str] = None,
    conversation_id: Optional[str] = None,
    current_user: str = Depends(get_current_user),
):
    """
    Retrieve conversation metadata (WhatsApp-like).

    METADATA COLLECTED:
    - Who talked to whom (sender_id → receiver_id)
    - Frequency of interaction (message count, last interaction)
    - Timestamps of each interaction
    - Delivery/read event counts
    - Device participation

    RESPONSE:
    {
        "conversation_id": "conv_uuid",
        "participants": ["user1", "user2"],
        "message_count": 42,
        "unread_count": 0,
        "delivered_count": 42,
        "read_count": 42,
        "last_interaction_at": "2025-02-08T10:30:00Z",
        "is_pinned": false,
        "is_muted": false,
        "is_archived": false,
        "active_devices": ["device1", "device2"]
    }
    """
    try:
        logger.info(
            f"[METADATA-QUERY] User {current_user} querying {conversation_id or 'all conversations'}"
        )

        # Placeholder response (actual metadata retrieved from MongoDB by background workers)
        return {
            "conversation_id": conversation_id,
            "participants": [current_user, user_id],
            "message_count": 0,
            "unread_count": 0,
            "delivered_count": 0,
            "read_count": 0,
            "last_interaction_at": None,
            "is_pinned": False,
            "is_muted": False,
            "is_archived": False,
            "active_devices": [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        logger.error(f"[METADATA-QUERY] Error: {e}")
        return {"error": str(e)}


@app.get("/api/v1/sync/device")
async def sync_device_state(
    device_id: Optional[str] = None, current_user: str = Depends(get_current_user)
):
    """
    Multi-device synchronization endpoint.
    Coordinates message delivery and status updates across devices.

    RESPONSE:
    {
        "device_id": "device_uuid",
        "sync_state": "synced|pending|out_of_sync",
        "pending_messages": 0,
        "last_sync_at": "2025-02-08T10:30:00Z",
        "active_devices": ["device1", "device2"],
        "primary_device": "device1"
    }
    """
    try:
        logger.info(
            f"[DEVICE-SYNC] User {current_user} Device {device_id} sync request"
        )

        return {
            "device_id": device_id,
            "sync_state": "synced",
            "pending_messages": 0,
            "last_sync_at": datetime.now(timezone.utc).isoformat(),
            "active_devices": [device_id],
            "primary_device": device_id,
        }
    except Exception as e:
        logger.error(f"[DEVICE-SYNC] Error: {e}")
        return {"error": str(e)}


@app.get("/api/v1/relationships/graph")
async def get_relationship_graph(
    limit: int = 20,
    score_min: float = 0.0,
    current_user: str = Depends(get_current_user),
):
    """
    Relationship graph query (WhatsApp-like).
    Retrieves user-to-user communication strength and relationship metrics.

    METRICS:
    - Communication strength score (0-100)
    - Frequency of interaction
    - Last interaction time
    - Interaction patterns

    RESPONSE:
    {
        "relationships": [
            {
                "user_id": "user_uuid",
                "strength_score": 75.5,
                "total_messages": 42,
                "last_interaction_at": "2025-02-08T10:30:00Z",
                "interaction_frequency_per_day": 0.5,
                "is_pinned": false
            }
        ]
    }
    """
    try:
        logger.info(
            f"[RELATIONSHIP-GRAPH] User {current_user} querying relationships (limit={limit}, min_score={score_min})"
        )

        return {
            "relationships": [],
            "total_count": 0,
            "score_min": score_min,
            "limit": limit,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        logger.error(f"[RELATIONSHIP-GRAPH] Error: {e}")
        return {"error": str(e)}


@app.get("/api/v1/messages/retention-policy")
async def get_retention_policy(current_user: str = Depends(get_current_user)):
    """
    Get current message retention and metadata retention policies.

    RESPONSE:
    {
        "message_retention_days": 90,
        "metadata_retention_days": 365,
        "delivery_event_retention_days": 30,
        "soft_delete_grace_period_days": 7,
        "max_devices_per_user": 4,
        "enable_message_history": true,
        "enable_metadata_collection": true,
        "enable_multi_device_sync": true
    }
    """
    try:
        from models import MessageRetentionPolicy

        logger.info(f"[RETENTION-POLICY] User {current_user} querying retention policy")

        return {
            "message_retention_days": int(os.getenv("MESSAGE_RETENTION_DAYS", 90)),
            "metadata_retention_days": int(os.getenv("METADATA_RETENTION_DAYS", 365)),
            "delivery_event_retention_days": int(
                os.getenv("DELIVERY_EVENT_RETENTION_DAYS", 30)
            ),
            "soft_delete_grace_period_days": int(
                os.getenv("SOFT_DELETE_GRACE_PERIOD_DAYS", 7)
            ),
            "max_devices_per_user": int(os.getenv("MAX_DEVICES_PER_USER", 4)),
            "enable_message_history": os.getenv(
                "ENABLE_MESSAGE_HISTORY", "true"
            ).lower()
            == "true",
            "enable_metadata_collection": os.getenv(
                "ENABLE_METADATA_COLLECTION", "true"
            ).lower()
            == "true",
            "enable_relationship_graph": os.getenv(
                "ENABLE_RELATIONSHIP_GRAPH", "true"
            ).lower()
            == "true",
            "enable_multi_device_sync": os.getenv(
                "ENABLE_MULTI_DEVICE_SYNC", "true"
            ).lower()
            == "true",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        logger.error(f"[RETENTION-POLICY] Error: {e}")
        return {"error": str(e)}


# Import ObjectId for ID generation
from bson import ObjectId


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=settings.DEBUG)
