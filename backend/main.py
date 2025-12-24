from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
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
    from backend.database import connect_db, close_db
    print("[STARTUP] ✓ database module imported")
except Exception as e:
    print(f"[STARTUP] ✗ Failed to import database: {e}")
    raise

try:
    from backend.routes import auth, files, chats, users, updates, p2p_transfer, groups, messages, channels, debug
    print("[STARTUP] ✓ routes modules imported")
except Exception as e:
    print(f"[STARTUP] ✗ Failed to import routes: {e}")
    raise

try:
    from backend.config import settings
    print("[STARTUP] ✓ config module imported")
    print(f"[STARTUP] MongoDB URI (sanitized): {settings.MONGODB_URI.split('@')[-1] if '@' in settings.MONGODB_URI else 'invalid'}")
    print(f"[STARTUP] DEBUG mode: {settings.DEBUG}")
except Exception as e:
    print(f"[STARTUP] ✗ Failed to import config: {e}")
    raise

try:
    from backend.mongo_init import ensure_mongodb_ready
    print("[STARTUP] ✓ mongo_init module imported")
except Exception as e:
    print(f"[STARTUP] ✗ Failed to import mongo_init: {e}")
    raise

try:
    from backend.security import SecurityConfig
    print("[STARTUP] ✓ security module imported")
except Exception as e:
    print(f"[STARTUP] ✗ Failed to import security: {e}")
    raise

try:
    from backend.error_handlers import register_exception_handlers
    print("[STARTUP] ✓ error_handlers module imported")
except Exception as e:
    print(f"[STARTUP] ✗ Failed to import error_handlers: {e}")
    raise

print("[STARTUP] All imports successful!")


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
        try:
            result = await ensure_mongodb_ready()
            if result:
                print("[DB] MongoDB initialization completed successfully")
            else:
                print("[DB] MongoDB initialization skipped or incomplete - will initialize on first use")
        except Exception as e:
            print(f"[WARN] MongoDB initialization warning: {str(e)}")
            print("[WARN] Continuing startup - collections will be created on first use")
        
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
    lifespan=lifespan
)

# Register custom exception handlers
register_exception_handlers(app)

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
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition", "X-Total-Count"],
    max_age=600,  # Cache preflight requests for 10 minutes
)

# ✅ CRITICAL FIX: Handle CORS preflight requests (OPTIONS) without requiring authentication
# Browser CORS preflight requests don't have auth headers, so they would fail 401 without this
# NOTE: FastAPI automatically handles OPTIONS for registered routes, this is fallback only
@app.options("/{full_path:path}")
async def handle_options_request(full_path: str):
    """
    Handle CORS preflight OPTIONS requests.
    These must succeed without authentication for CORS to work in browsers.
    """
    return Response(status_code=200, headers={
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
    })

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


@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "app": "Hypersend",
        "version": "1.0.0",
        "status": "running",
        "environment": "debug" if settings.DEBUG else "production"
    }


# Serve favicon (avoid 404 in logs)
FAVICON_PATH = Path("frontend/assets/favicon.ico")

@app.get("/favicon.ico")
async def favicon():
    if FAVICON_PATH.exists():
        return FileResponse(str(FAVICON_PATH))
    return Response(status_code=204)


@app.get("/health")
async def health():
    """Health check"""
    return {"status": "healthy"}


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

# Include debug routes (only in DEBUG mode, but router checks internally)
if settings.DEBUG:
    app.include_router(debug.router, prefix="/api/v1")
    print("[STARTUP] ✓ Debug routes registered")




if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.DEBUG
    )
