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

# Early diagnostic logging
print("[STARTUP] Python version:", sys.version)
print("[STARTUP] Python path:", sys.path)
print("[STARTUP] Current working directory:", os.getcwd())
print("[STARTUP] Starting backend imports...")

try:
    # Add current directory to Python path for Docker
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent))
    from datetime import datetime, timezone
    
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
    """Middleware to validate requests and prevent common 4xx errors"""
    
    async def dispatch(self, request, call_next):
        """Validate request before processing"""
        try:
            # Check Content-Length for POST/PUT/PATCH (411)
            if request.method in ["POST", "PUT", "PATCH"]:
                content_length_header = request.headers.get("content-length")
                
                if not content_length_header and request.method != "GET":
                    # Try to check if there's a body without Content-Length
                    try:
                        body = await request.body()
                        if body and not content_length_header:
                            # Log but allow (fastapi might handle)
                            logger.warning(f"[411] Missing Content-Length for {request.method} {request.url.path}")
                    except:
                        pass
                
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
                                    "path": str(request.url.path),
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
                                "path": str(request.url.path),
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
                        "path": str(request.url.path),
                        "method": request.method,
                        "hints": ["Shorten the URL", "Use POST for complex queries"]
                    }
                )
            
            # Check Content-Type for POST/PUT (415 - though Pydantic usually catches)
            if request.method in ["POST", "PUT", "PATCH"]:
                content_type = request.headers.get("content-type", "")
                if not content_type:
                    # Some requests can work without explicit Content-Type
                    logger.debug(f"[415] No Content-Type for {request.method} {request.url.path}")
            
            response = await call_next(request)
            return response
            
        except Exception as e:
            logger.error(f"[MIDDLEWARE_ERROR] {request.method} {request.url.path}: {str(e)}", exc_info=True)
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={
                    "status_code": 500,
                    "error": "Internal Server Error",
                    "detail": "Server error processing request",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "path": str(request.url.path),
                    "method": request.method,
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
        
        # Connect to database with error handling
        try:
            await connect_db()
            print("[DB] Database connection established")
        except Exception as e:
            if settings.USE_MOCK_DB:
                print("[DB] Mock database initialized")
            else:
                print(f"[WARN] Database connection failed (continuing in offline mode): {str(e)}")
                print("[WARN] WARNING: Database operations will fail - used for development/testing only!")
                # Don't raise - allow app to start for testing
                pass
        
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

# Add a catch-all exception handler for any unhandled exceptions
@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Catch-all exception handler for any unhandled exceptions"""
    import traceback
    logger.error(f"[UNCAUGHT_EXCEPTION] {type(exc).__name__}: {str(exc)}")
    if settings.DEBUG:
        traceback.print_exc()
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "status_code": 500,
            "error": "Internal Server Error",
            "detail": "An unexpected error occurred" if not settings.DEBUG else str(exc),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "path": str(request.url.path),
            "method": request.method,
        }
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Log detailed validation errors"""
    errors = exc.errors()
    logger.error(f"[VALIDATION_ERROR] Path: {request.url.path} - Errors: {errors}")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": errors},
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
# FIX: Ensure CORS is properly configured with fallback origins
cors_origins = settings.CORS_ORIGINS
# If CORS_ORIGINS contains the asterisk, convert to list with asterisk
if isinstance(cors_origins, str):
    cors_origins = [cors_origins]
if isinstance(cors_origins, list) and len(cors_origins) > 0:
    # Clean up whitespace in origins
    cors_origins = [origin.strip() for origin in cors_origins]
    # If wildcard present, keep it; otherwise add local fallbacks
    if "*" not in cors_origins:
        local_origins = ["http://localhost", "http://localhost:8000", "http://127.0.0.1:8000"]
        for origin in local_origins:
            if origin not in cors_origins:
                cors_origins.append(origin)

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition", "X-Total-Count", "Access-Control-Allow-Origin", "Access-Control-Allow-Methods", "Access-Control-Allow-Headers"],
    max_age=3600,  # Cache preflight requests for 1 hour
)

# ✅ CRITICAL FIX: Handle CORS preflight requests (OPTIONS) without requiring authentication
# Browser CORS preflight requests don't have auth headers, so they would fail 401 without this
# NOTE: FastAPI automatically handles OPTIONS for registered routes, this is fallback only
@app.options("/{full_path:path}")
async def handle_options_request(full_path: str, request: Request):
    """
    Handle CORS preflight OPTIONS requests.
    These must succeed without authentication for CORS to work in browsers.
    SECURITY: Use exact regex matching to prevent origin bypass attacks
    (e.g., https://evildomain.yourdomain.com would bypass substring matching)
    """
    import re
    origin = request.headers.get("Origin")
    
    # SECURITY FIX: Use regex instead of substring matching to prevent bypasses
    # Substring matching allows: evildomain.com, localhostevil.com, etc.
    allowed_origin = "null"  # Default deny-all for untrusted origins
    
    if origin:
        # Whitelist patterns with proper boundary matching
        # Production URLs should be configured via environment variables
        allowed_patterns = [
            r'^http://localhost(:[0-9]+)?$',             # localhost with optional port
            r'^http://127\.0\.0\.1(:[0-9]+)?$',        # 127.0.0.1 with optional port
            r'^https?://([a-zA-Z0-9-]+\.)?yourdomain\.com(:[0-9]+)?$',  # Replace with your domain
        ]
        
        for pattern in allowed_patterns:
            if re.match(pattern, origin):
                allowed_origin = origin
                break
    
    return Response(
        status_code=204,
        headers={
            "Access-Control-Allow-Origin": allowed_origin,
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, HEAD",
            "Access-Control-Allow-Headers": "Content-Type, Authorization, Accept, Origin, X-Requested-With",
            "Access-Control-Allow-Credentials": "true" if allowed_origin != "null" else "false",
            "Access-Control-Max-Age": "86400",
        }
    )

# Health check endpoint for monitoring and CORS testing
@app.get("/health")
async def health_check():
    """
    Health check endpoint - used to verify API is running.
    Accessible from browser without authentication (no CORS issues).
    """
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "api_base_url": settings.API_BASE_URL,
        "debug_mode": settings.DEBUG,
    }

# Diagnostic endpoint to help debug connection issues
@app.get("/api/v1/health")
async def api_health_check(request: Request):
    """
    API health endpoint with diagnostic info
    Used to verify API endpoint is accessible from frontend
    """
    try:
        client_ip = request.client.host if request.client else "unknown"
    except:
        client_ip = "unknown"
    
    return {
        "status": "healthy",
        "service": "Hypersend API",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "client_ip": client_ip,
        "api_base_url": settings.API_BASE_URL,
        "debug_mode": settings.DEBUG,
        "message": "API endpoint is reachable and responding properly"
    }

# API version endpoint
@app.get("/api/v1/health")
async def api_health_check():
    """
    API health check endpoint under /api/v1 path.
    """
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "api_base_url": settings.API_BASE_URL,
        "debug_mode": settings.DEBUG,
    }

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


# Serve favicon (avoid 404 in logs)
FAVICON_PATH = Path("frontend/assets/favicon.ico")

@app.get("/favicon.ico")
async def favicon():
    if FAVICON_PATH.exists():
        return FileResponse(str(FAVICON_PATH))
    return Response(status_code=204)

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



# Include routers
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

# OPTIONS preflight handlers for alias endpoints
@app.options("/api/v1/login")
@app.options("/api/v1/register")
@app.options("/api/v1/refresh")
@app.options("/api/v1/logout")
async def preflight_alias_endpoints():
    """Handle CORS preflight for alias endpoints"""
    return Response(status_code=204, headers={
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
    })

# Create simple redirect aliases - just accept and forward to auth handlers
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
    print("[STARTUP] ✓ Debug routes registered")




if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.DEBUG
    )
