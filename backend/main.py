from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pathlib import Path
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from database import connect_db, close_db
from routes import auth, files, chats, users, updates, p2p_transfer, groups, messages, channels
from config import settings
from mongo_init import ensure_mongodb_ready
from security import SecurityConfig


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup and shutdown events"""
    # Startup
    try:
        print(f"[START] Zaply API starting on {settings.API_HOST}:{settings.API_PORT}")
        print(f"[START] Environment: {'DEBUG' if settings.DEBUG else 'PRODUCTION'}")
        print("[DB] Initializing MongoDB...")
        
        # Initialize MongoDB (create users, collections, indexes)
        try:
            await ensure_mongodb_ready()
            print("[DB] MongoDB initialization completed")
        except Exception as e:
            print(f"[ERROR] MongoDB initialization failed: {str(e)}")
            print("[ERROR] Please check MongoDB connection and configuration")
            raise
        
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
            print(f"[ERROR] Database connection failed: {str(e)}")
            print("[ERROR] Please check:")
            print("  - MongoDB is running")
            print("  - Connection string is correct")
            print("  - Network connectivity")
            raise
        
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


app = FastAPI(
    title="Zaply API",
    description="Secure peer-to-peer file transfer and messaging application",
    version="1.0.0",
    lifespan=lifespan
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
        "app": "Zaply",
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




if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.DEBUG
    )
