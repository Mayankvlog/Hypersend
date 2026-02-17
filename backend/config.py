import os
import sys
from pathlib import Path
from dotenv import load_dotenv
from urllib.parse import quote_plus
import secrets

# Load environment variables from .env file
env_path = Path(__file__).parent / ".env"
print(f"[CONFIG] Looking for .env at: {env_path}")
if env_path.exists():
    print(f"[CONFIG] Loading .env from: {env_path}")
    load_dotenv(dotenv_path=env_path)
else:
    print(f"[CONFIG] .env not found at: {env_path}")

# Also check parent directory
env_path_parent = Path(__file__).parent.parent / ".env"
if env_path_parent.exists():
    print(f"[CONFIG] Loading .env from parent: {env_path_parent}")
    load_dotenv(dotenv_path=env_path_parent)

# Also check current directory
if not os.getenv("MONGODB_URI") and not os.getenv("MONGO_USER"):
    print("[CONFIG] Loading .env from current directory")
    load_dotenv()


class Settings:
    # MongoDB Connection
    # For development, use MongoDB Atlas or local MongoDB
    # Read MongoDB credentials from environment
    _IS_DOCKER: bool = os.path.exists("/.dockerenv")
    _MONGO_USER: str = os.getenv("MONGO_USER", "zaply")
    _MONGO_PASSWORD: str = os.getenv("MONGO_PASSWORD", "zaply_secure_password")
    _MONGO_HOST: str = os.getenv("MONGO_HOST", "mongodb" if _IS_DOCKER else "localhost")
    _MONGO_PORT: str = os.getenv("MONGO_PORT", "27017")
    _MONGO_DB: str = os.getenv("MONGO_INITDB_DATABASE", "zaply")
    _MONGODB_ATLAS_ENABLED: bool = os.getenv("MONGODB_ATLAS_ENABLED", "false").lower() in ("true", "1", "yes")
    
    # Priority order for MongoDB URI:
    # 1. If MongoDB Atlas is explicitly enabled and MONGODB_URI is set from environment
    # 2. If running in Docker - use internal MongoDB
    # 3. If MONGODB_URI is set in environment - use it (supports both Atlas and traditional)
    # 4. Otherwise - construct from individual components
    
    # Determine MongoDB connection method
    from urllib.parse import quote_plus
    
    # CRITICAL: MONGODB_URI must be set - fail fast if missing
    env_mongodb_uri = os.getenv("MONGODB_URI")
    
    if not env_mongodb_uri:
        raise RuntimeError(
            "CRITICAL: MONGODB_URI environment variable is required. "
            "No hardcoded fallback is permitted for security reasons. "
            "Please set MONGODB_URI in your environment file (e.g., .env or .env.production)"
        )
    
    # Validate MongoDB URI format
    if not (env_mongodb_uri.startswith("mongodb://") or env_mongodb_uri.startswith("mongodb+srv://")):
        raise ValueError(
            f"MONGODB_URI must start with 'mongodb://' or 'mongodb+srv://'. "
            f"Got: {env_mongodb_uri[:50]}..."
        )
    
    MONGODB_URI: str = env_mongodb_uri
    
    # Log connection info without exposing credentials
    if "mongodb+srv://" in env_mongodb_uri:
        print(f"[CONFIG] MongoDB connection: Atlas (Cloud) - from environment")
    else:
        print(f"[CONFIG] MongoDB connection: Traditional MongoDB - from environment")
    
    # Log connection info without exposing credentials
    if '@' in MONGODB_URI:
        try:
            if "mongodb+srv://" in MONGODB_URI:
                # For Atlas URIs, show cluster info
                cluster_part = MONGODB_URI.split('@')[1].split('/')[0]
                print(f"[CONFIG] MongoDB Atlas cluster: {cluster_part}")
            else:
                # For traditional URIs, show host:port
                host_info = MONGODB_URI.split('@')[1].split('/')[0]
                print(f"[CONFIG] MongoDB connection host: {host_info}")
        except Exception as e:
            print(f"[CONFIG] MongoDB URI configured (error parsing details: {str(e)})")
    
    # Security
    # SECRET_KEY must be set in production - no fallbacks allowed
    _env_secret = os.getenv("SECRET_KEY")
    if not _env_secret:
        raise ValueError("SECRET_KEY environment variable must be set in production")
    SECRET_KEY: str = _env_secret
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    
    # Token expiration constants
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
    REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "30"))
    UPLOAD_TOKEN_EXPIRE_HOURS: int = int(os.getenv("UPLOAD_TOKEN_EXPIRE_HOURS", "480"))  # Extended tokens for large uploads
    UPLOAD_TOKEN_DURATION: int = UPLOAD_TOKEN_EXPIRE_HOURS * 3600
    
    # QR Code session expiration
    QR_CODE_SESSION_EXPIRE_MINUTES: int = int(os.getenv("QR_CODE_SESSION_EXPIRE_MINUTES", "5"))
    PASSWORD_RESET_EXPIRE_MINUTES: int = int(os.getenv("PASSWORD_RESET_EXPIRE_MINUTES", "30"))
    
    # File Storage (WhatsApp-style: Local only)
    STORAGE_MODE: str = os.getenv("STORAGE_MODE", "local")  # local, server, or hybrid
    DATA_ROOT: Path = Path(os.getenv("DATA_ROOT", "./data"))  # Only for metadata/temp
    UPLOAD_DIR: str = os.getenv("UPLOAD_DIR", "./uploads")  # Upload directory for chunks
    CHUNK_SIZE: int = int(os.getenv("CHUNK_SIZE", "4194304"))  # 4 MiB
    UPLOAD_CHUNK_SIZE: int = CHUNK_SIZE
    MAX_FILE_SIZE_BYTES: int = int(os.getenv("MAX_FILE_SIZE_BYTES", "16106127360"))  # 15 GiB
    USER_QUOTA_BYTES: int = int(os.getenv("USER_QUOTA_BYTES", str(10 * 1024 * 1024 * 1024)))  # 10 GB default
    MAX_PARALLEL_CHUNKS: int = int(os.getenv("MAX_PARALLEL_CHUNKS", "4"))
    FILE_RETENTION_HOURS: int = int(os.getenv("FILE_RETENTION_HOURS", "0"))  # 0 = no server storage
    UPLOAD_EXPIRE_HOURS: int = int(os.getenv("UPLOAD_EXPIRE_HOURS", "72"))  # Extended to 72 hours (3 days) for very large files
    
    # Enhanced timeout settings for large file transfers
    CHUNK_UPLOAD_TIMEOUT_SECONDS: int = int(os.getenv("CHUNK_UPLOAD_TIMEOUT_SECONDS", "600"))  # 10 minutes per chunk (for 15GB files)
    FILE_ASSEMBLY_TIMEOUT_MINUTES: int = int(os.getenv("FILE_ASSEMBLY_TIMEOUT_MINUTES", "30"))  # 30 minutes for assembly (15GB)
    MAX_UPLOAD_RETRY_ATTEMPTS: int = int(os.getenv("MAX_UPLOAD_RETRY_ATTEMPTS", "5"))  # More retries for large files
    
    # Large file handling optimizations
    LARGE_FILE_THRESHOLD_GB: int = int(os.getenv("LARGE_FILE_THRESHOLD_GB", "1"))  # Files > 1GB get special handling
    LARGE_FILE_THRESHOLD: int = LARGE_FILE_THRESHOLD_GB * 1024 * 1024 * 1024
    LARGE_FILE_CHUNK_TIMEOUT_SECONDS: int = int(os.getenv("LARGE_FILE_CHUNK_TIMEOUT_SECONDS", "900"))  # 15 minutes for large file chunks

    # Upload token durations
    UPLOAD_TOKEN_DURATION_LARGE: int = int(os.getenv("UPLOAD_TOKEN_DURATION_LARGE", str(UPLOAD_TOKEN_DURATION)))
    
    # API
    API_HOST: str = os.getenv("API_HOST", "0.0.0.0")
    API_PORT: int = int(os.getenv("API_PORT", "8000"))  # Backend listens on 8000, Nginx proxies to it
    # Default public API base URL for this deployment
    # PROD: https://your-production-domain/api/v1 (requires DNS + SSL)
    # DEV: Use local backend API endpoint
    API_BASE_URL: str = os.getenv("API_BASE_URL", "https://zaply.in.net/api/v1")
    
    # Rate Limiting
    RATE_LIMIT_PER_USER: int = int(os.getenv("RATE_LIMIT_PER_USER", "100"))
    RATE_LIMIT_WINDOW_SECONDS: int = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))

    # Email / SMTP (optional - used for password reset emails)
    SMTP_HOST: str = os.getenv("SMTP_HOST", "")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USERNAME: str = os.getenv("SMTP_USERNAME", "")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
    SMTP_USE_TLS: bool = os.getenv("SMTP_USE_TLS", "True").lower() in ("true", "1", "yes")
    EMAIL_FROM: str = os.getenv("EMAIL_FROM", "")
    
    # Redis Configuration (WhatsApp-style: Ephemeral Messages Only)
    # MANDATORY: All settings enforce in-memory only, NO persistence
    REDIS_HOST: str = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT: int = int(os.getenv("REDIS_PORT", "6379"))
    REDIS_PASSWORD: str = os.getenv("REDIS_PASSWORD", "")
    REDIS_DB: int = int(os.getenv("REDIS_DB", "0"))
    REDIS_URL: str = os.getenv("REDIS_URL", f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}")
    # WHATSAPP MESSAGE STORAGE: Redis is ONLY temporary store
    MESSAGE_STORAGE: str = os.getenv("MESSAGE_STORAGE", "redis_only")  # redis_only = WhatsApp style
    MESSAGE_TTL_MINUTES: int = int(os.getenv("MESSAGE_TTL_MINUTES", "60"))  # Messages expire after 1 hour
    MESSAGE_TTL_SECONDS: int = MESSAGE_TTL_MINUTES * 60  # Convert to seconds for Redis
    # CRITICAL: Messages older than TTL are DELETED (acceptable, user device has backup)
    REDIS_MAX_CONNECTIONS: int = int(os.getenv("REDIS_MAX_CONNECTIONS", "100"))
    REDIS_SOCKET_TIMEOUT: int = int(os.getenv("REDIS_SOCKET_TIMEOUT", "5"))
    REDIS_SOCKET_CONNECT_TIMEOUT: int = int(os.getenv("REDIS_SOCKET_CONNECT_TIMEOUT", "5"))
    REDIS_MAX_MEMORY: str = os.getenv("REDIS_MAX_MEMORY", "2gb")  # 2GB for ephemeral messages
    
    # Email service validation with enhanced checking
    EMAIL_SERVICE_ENABLED: bool = bool(SMTP_HOST and SMTP_USERNAME and SMTP_PASSWORD and EMAIL_FROM)
    
    # Email rate limiting (prevent spam)
    EMAIL_RATE_LIMIT_PER_HOUR: int = int(os.getenv("EMAIL_RATE_LIMIT_PER_HOUR", "10"))
    EMAIL_RATE_LIMIT_PER_DAY: int = int(os.getenv("EMAIL_RATE_LIMIT_PER_DAY", "50"))
    
    # Email service auto-configuration for development
    EMAIL_AUTO_CONFIGURE: bool = os.getenv("EMAIL_AUTO_CONFIGURE", "False").lower() in ("true", "1", "yes")
    
    # Fallback email configuration for development
    EMAIL_FALLBACK_ENABLED: bool = os.getenv("EMAIL_FALLBACK_ENABLED", "True").lower() in ("true", "1", "yes")
    
    # Development
    # Default DEBUG to True for development; set to False in production with proper SECRET_KEY
    DEBUG: bool = os.getenv("DEBUG", "True").lower() in ("true", "1", "yes")
    
    # SSL Certificate Validation (defined after DEBUG)
    # CRITICAL: Controls whether to verify SSL certificates for external API calls
    # Development: Can be disabled for self-signed certificates
    # Production: MUST be True for security
    VERIFY_SSL_CERTIFICATES: bool = os.getenv("VERIFY_SSL_CERTIFICATES", "False").lower() in ("true", "1", "yes")
    
    # SSL Certificate Bundle Path (for custom CA certificates)
    # Leave empty to use system default certificates
    SSL_CERT_BUNDLE: str = os.getenv("SSL_CERT_BUNDLE", "")
    
    # SSL Certificate Verification Mode
    # Options: "strict" (verify all), "relaxed" (allow self-signed in dev), "disabled" (no verification)
    SSL_VERIFY_MODE: str = os.getenv("SSL_VERIFY_MODE", "relaxed" if DEBUG else "strict")
    
    # Detect if running under pytest
    _IS_TESTING: bool = "pytest" in sys.modules
    
    # Mock mode for testing without MongoDB - CRITICAL: Default to False for production
    USE_MOCK_DB: bool = os.getenv("USE_MOCK_DB", "False").lower() in ("true", "1", "yes")
    print(f"[CONFIG] USE_MOCK_DB: {USE_MOCK_DB}")
    print(f"[CONFIG] Is Testing (pytest): {_IS_TESTING}")
    if USE_MOCK_DB:
        print("[CONFIG] WARNING: USING MOCK DATABASE - FOR TESTING ONLY")
    else:
        print("[CONFIG] Using real MongoDB Atlas database - Production mode")
    
    # Email / SMTP (optional - used for password reset emails)
    ENABLE_PASSWORD_RESET: bool = os.getenv("ENABLE_PASSWORD_RESET", "True").lower() in ("true", "1", "yes")
    if not ENABLE_PASSWORD_RESET:
        print("[CONFIG] Password reset functionality disabled")
    
    ENABLE_EMAIL: bool = os.getenv("ENABLE_EMAIL", "True").lower() in ("true", "1", "yes")
    if not ENABLE_EMAIL:
        print("[CONFIG] Email notifications disabled")
    
    # WhatsApp Storage Model (User Device + 24h S3 TTL)
    STORAGE_MODE: str = os.getenv("STORAGE_MODE", "user_device_s3")  # WhatsApp: User Device + 24h S3 TTL
    S3_BUCKET: str = os.getenv("S3_BUCKET", "zaply-temp")
    AWS_ACCESS_KEY_ID: str = os.getenv("AWS_ACCESS_KEY_ID", "")
    AWS_SECRET_ACCESS_KEY: str = os.getenv("AWS_SECRET_ACCESS_KEY", "")
    AWS_REGION: str = os.getenv("AWS_REGION", "us-east-1")
    
    # WhatsApp Storage Configuration
    SERVER_STORAGE_BYTES: int = int(os.getenv("SERVER_STORAGE_BYTES", "0"))
    WHATSAPP_STORAGE: bool = os.getenv("WHATSAPP_STORAGE", "True").lower() in ("true", "1", "yes")
    FILE_TTL_SECONDS: int = int(os.getenv("FILE_TTL_SECONDS", "86400"))  # 24 hours
    USER_DEVICE_ONLY: bool = os.getenv("USER_DEVICE_ONLY", "True").lower() in ("true", "1", "yes")
    NO_SERVER_MEDIA: bool = os.getenv("NO_SERVER_MEDIA", "True").lower() in ("true", "1", "yes")
    
    # WhatsApp Storage Validation
    if WHATSAPP_STORAGE:
        print(f"[CONFIG] WhatsApp Storage Model: ENABLED")
        print(f"[CONFIG] Server Storage: {SERVER_STORAGE_BYTES} bytes (ZERO)")
        print(f"[CONFIG] File TTL: {FILE_TTL_SECONDS} seconds (24h)")
        print(f"[CONFIG] User Device Only: {USER_DEVICE_ONLY}")
        print(f"[CONFIG] No Server Media: {NO_SERVER_MEDIA}")
    else:
        print(f"[CONFIG] Traditional Storage Model: ENABLED")
    
    # Additional WhatsApp Storage Variables
    FILE_TTL_HOURS: int = int(os.getenv("FILE_TTL_HOURS", "24"))  # 24h temp only like WhatsApp
    USER_DEVICE_STORAGE: bool = os.getenv("USER_DEVICE_STORAGE", "True").lower() in ("true", "1", "yes")
    COST_MODEL: str = os.getenv("COST_MODEL", "free")  # No server storage cost
    
    # For backward compatibility - define paths but they won't be used in S3 mode
    UPLOADS_PATH: str = os.getenv("UPLOADS_PATH", "/app/uploads")
    MEDIA_PATH: str = os.getenv("MEDIA_PATH", "/app/media")
    DOCUMENTS_PATH: str = os.getenv("DOCUMENTS_PATH", "/app/documents")
    IMAGES_PATH: str = os.getenv("IMAGES_PATH", "/app/images")
    VIDEOS_PATH: str = os.getenv("VIDEOS_PATH", "/app/videos")
    AUDIO_PATH: str = os.getenv("AUDIO_PATH", "/app/audio")
    USER_FILES_PATH: str = os.getenv("USER_FILES_PATH", "/app/user_files")
    CHAT_FILES_PATH: str = os.getenv("CHAT_FILES_PATH", "/app/chat_files")
    TEMP_PATH: str = os.getenv("TEMP_PATH", "/app/temp")
    THUMBNAILS_PATH: str = os.getenv("THUMBNAILS_PATH", "/app/thumbnails")
    
    # WhatsApp-like File Management with 15GB Support
    FILE_RETENTION_HOURS: int = int(os.getenv("FILE_RETENTION_HOURS", "0"))  # 0 hours - immediate deletion
    TEMP_FILE_RETENTION_HOURS: int = int(os.getenv("TEMP_FILE_RETENTION_HOURS", "0"))  # 0 hours - immediate deletion
    AUTO_CLEANUP_ENABLED: bool = os.getenv("AUTO_CLEANUP_ENABLED", "True").lower() in ("true", "1", "yes")
    MAX_STORAGE_PER_USER_GB: int = int(os.getenv("MAX_STORAGE_PER_USER_GB", "0"))  # 0GB - no server storage
    
    # 15GB Maximum File Size Support
    MAX_FILE_SIZE_MB: int = int(os.getenv("MAX_FILE_SIZE_MB", "15360"))  # 15GB in MB
    MAX_FILE_SIZE_BYTES: int = int(os.getenv("MAX_FILE_SIZE_BYTES", str(15 * 1024 * 1024 * 1024)))  # 15GB in bytes
    LARGE_FILE_THRESHOLD_GB: int = int(os.getenv("LARGE_FILE_THRESHOLD_GB", "1"))  # 1GB threshold
    LARGE_FILE_THRESHOLD: int = LARGE_FILE_THRESHOLD_GB * 1024 * 1024 * 1024
    
    # WhatsApp-like File Type Limits (Updated for 15GB support)
    MAX_IMAGE_SIZE_MB: int = int(os.getenv("MAX_IMAGE_SIZE_MB", "4096"))  # 4GB for high-res images
    MAX_VIDEO_SIZE_MB: int = int(os.getenv("MAX_VIDEO_SIZE_MB", "15360"))  # 15GB for videos
    MAX_AUDIO_SIZE_MB: int = int(os.getenv("MAX_AUDIO_SIZE_MB", "2048"))  # 2GB for audio
    MAX_DOCUMENT_SIZE_MB: int = int(os.getenv("MAX_DOCUMENT_SIZE_MB", "15360"))  # 15GB for documents
    
    # Convert to bytes
    MAX_IMAGE_SIZE_BYTES: int = MAX_IMAGE_SIZE_MB * 1024 * 1024
    MAX_VIDEO_SIZE_BYTES: int = MAX_VIDEO_SIZE_MB * 1024 * 1024
    MAX_AUDIO_SIZE_BYTES: int = MAX_AUDIO_SIZE_MB * 1024 * 1024
    MAX_DOCUMENT_SIZE_BYTES: int = MAX_DOCUMENT_SIZE_MB * 1024 * 1024
    
    # WhatsApp-like Supported File Types
    SUPPORTED_IMAGE_TYPES: list = os.getenv("SUPPORTED_IMAGE_TYPES", 
        "jpg,jpeg,png,gif,webp,bmp,heic,heif").split(",")
    SUPPORTED_VIDEO_TYPES: list = os.getenv("SUPPORTED_VIDEO_TYPES", 
        "mp4,mov,avi,mkv,webm,3gp,m4v").split(",")
    SUPPORTED_AUDIO_TYPES: list = os.getenv("SUPPORTED_AUDIO_TYPES", 
        "mp3,wav,aac,m4a,ogg,flac,amr").split(",")
    SUPPORTED_DOCUMENT_TYPES: list = os.getenv("SUPPORTED_DOCUMENT_TYPES", 
        "pdf,doc,docx,xls,xlsx,ppt,pptx,txt,rtf,zip,rar").split(",")
    
    # WhatsApp-like Storage Paths by Type
    STORAGE_PATHS: dict = {
        "image": IMAGES_PATH,
        "video": VIDEOS_PATH,
        "audio": AUDIO_PATH,
        "document": DOCUMENTS_PATH,
        "user_file": USER_FILES_PATH,
        "chat_file": CHAT_FILES_PATH,
        "temp": TEMP_PATH,
        "thumbnail": THUMBNAILS_PATH,
        "media": MEDIA_PATH,
        "upload": UPLOADS_PATH
    }
    
    print(f"[CONFIG] WhatsApp Storage Model: {STORAGE_MODE}")
    print(f"[CONFIG] S3 Bucket: {S3_BUCKET}")
    print(f"[CONFIG] AWS Region: {AWS_REGION}")
    print(f"[CONFIG] File TTL: {FILE_TTL_HOURS} hours (24h like WhatsApp)")
    print(f"[CONFIG] Server Storage: {SERVER_STORAGE_BYTES} bytes (0 = no storage)")
    print(f"[CONFIG] User Device Storage: {USER_DEVICE_STORAGE}")
    print(f"[CONFIG] Cost Model: {COST_MODEL}")
    print(f"[CONFIG] File Retention: {FILE_RETENTION_HOURS} hours (immediate deletion)")
    print(f"[CONFIG] Auto Cleanup: {AUTO_CLEANUP_ENABLED}")
    print(f"[CONFIG] Max Storage/User: {MAX_STORAGE_PER_USER_GB}GB (0 = no server storage)")
    print(f"[CONFIG] Max File Size: {MAX_FILE_SIZE_MB}MB ({MAX_FILE_SIZE_MB//1024}GB)")
    print(f"[CONFIG] Large File Threshold: {LARGE_FILE_THRESHOLD_GB}GB")
    print(f"[CONFIG] Max Image Size: {MAX_IMAGE_SIZE_MB}MB")
    print(f"[CONFIG] Max Video Size: {MAX_VIDEO_SIZE_MB}MB")
    print(f"[CONFIG] Max Audio Size: {MAX_AUDIO_SIZE_MB}MB")
    print(f"[CONFIG] Max Document Size: {MAX_DOCUMENT_SIZE_MB}MB")
    
    # File upload settings (15GB Support)
    # LARGE_FILE_THRESHOLD and MAX_FILE_SIZE already set above
    # Remove duplicate assignments to avoid conflicts
    
    # CRITICAL: Production safety check
    # Allow mock DB if DEBUG is enabled OR if we're running under pytest
    if not DEBUG and USE_MOCK_DB and not _IS_TESTING:
        raise RuntimeError("PRODUCTION SAFETY ERROR: Mock database cannot be used in production. Set USE_MOCK_DB=False")
    
    # CORS Configuration
    # ENHANCED: Load from environment with secure defaults
    # PRODUCTION: Use specific allowed origins only
    cors_origins_default = [
        # Production origins
        "https://zaply.in.net",
        "https://www.zaply.in.net",
        # Docker internal names (keep for compose/k8s internal traffic)
        "http://zaply_frontend:80",
        "http://zaply_frontend",
        "http://frontend:80",
        "http://frontend",
        "http://zaply_backend:8000",
    ]

    CORS_ORIGINS = cors_origins_default

    def __init__(self):
        self.CORS_ORIGINS = self._get_cors_origins()
    
    # NOTE: CORS origins should be configured per environment - NEVER use wildcard "*" in production
    def _get_cors_origins(self) -> list:
        """Get CORS origins based on environment"""
        # Priority: ALLOWED_ORIGINS > CORS_ORIGINS > API_BASE_URL-derived > defaults
        env_allowed_origins = os.getenv("ALLOWED_ORIGINS")  # Highest priority: docker-compose
        env_cors_origins = os.getenv("CORS_ORIGINS")        # Alternative name
        env_api_base_url = os.getenv("API_BASE_URL")        # Used to derive domain
        origins: list = []
        https_origins: list = []
        
        # FIRST: Use ALLOWED_ORIGINS if explicitly provided (takes precedence)
        if env_allowed_origins:
            origins = [origin.strip() for origin in env_allowed_origins.split(",") if origin.strip()]
            if origins:
                # SECURITY: Filter out HTTP origins in production mode using self.DEBUG
                if not self.DEBUG:
                    # Production mode: Only allow HTTPS origins
                    https_origins = [origin for origin in origins if origin.startswith("https://")]
                    http_origins = [origin for origin in origins if origin.startswith("http://")]
                    
                    # Check if HTTP origins are Docker internal (safe) vs external (security risk)
                    external_http_origins = []
                    docker_http_origins = []
                    
                    for origin in http_origins:
                        if any(docker_host in origin for docker_host in ['zaply_frontend:', 'frontend:', 'localhost:8000', '127.0.0.1:3000']):
                            docker_http_origins.append(origin)
                        else:
                            external_http_origins.append(origin)
                    
                    if external_http_origins:
                        # Only warn about external HTTP origins (security risk)
                        print(f"[CORS_SECURITY] ⚠️  WARNING: Production mode with EXTERNAL HTTP origins detected!")
                        print(f"[CORS_SECURITY] ⚠️  External HTTP origins allow unencrypted traffic - SECURITY RISK!")
                        print(f"[CORS_SECURITY] ⚠️  External HTTP origins found: {external_http_origins}")
                        print(f"[CORS_SECURITY] ⚠️  Use HTTPS only in production deployment")
                    
                    if docker_http_origins:
                        print(f"[CORS_SECURITY] Docker internal HTTP origins (safe): {docker_http_origins}")
                     
                    if https_origins:
                        print(f"[CORS_SECURITY] OK Production CORS origins (HTTPS only): {https_origins}")
                return https_origins if https_origins else origins

            return origins

        if env_cors_origins:
            origins = [origin.strip() for origin in env_cors_origins.split(",") if origin.strip()]
            if origins:
                if not self.DEBUG:
                    https_origins = [origin for origin in origins if origin.startswith("https://")]
                    return https_origins if https_origins else origins
                return origins

        if env_api_base_url:
            derived = env_api_base_url.replace("/api/v1", "").strip()
            if derived:
                return [derived]

        return self.cors_origins_default
    
    def validate_email_config(self):
        """Validate email service configuration with enhanced checking"""
        if self.EMAIL_SERVICE_ENABLED:
            print(f"[EMAIL] Email service configured with host: {self.SMTP_HOST}")
            print(f"[EMAIL] Email from: {self.EMAIL_FROM}")
            print(f"[EMAIL] Rate limits: {self.EMAIL_RATE_LIMIT_PER_HOUR}/hour, {self.EMAIL_RATE_LIMIT_PER_DAY}/day")
            
            # Enhanced email format validation
            if '@' not in self.EMAIL_FROM or '.' not in self.EMAIL_FROM.split('@')[1]:
                print(f"[EMAIL] WARNING: Invalid email format: {self.EMAIL_FROM}")
            
            # Validate SMTP configuration
            self._validate_smtp_config()
            
            print("[EMAIL] Email service ready for use")
        else:
            # Only show email warning in debug mode to reduce log noise in production
            if self.DEBUG:
                print("[EMAIL] Email service NOT configured - password reset emails will not be sent")
                print("[EMAIL] To enable email, set: SMTP_HOST, SMTP_USERNAME, SMTP_PASSWORD, EMAIL_FROM")
            else:
                print("[EMAIL] Email service disabled (optional - configure SMTP for password reset)")
            
            if self.EMAIL_FALLBACK_ENABLED and self.DEBUG:
                print("[EMAIL] Fallback mode: Tokens returned in debug mode for testing")
            
            if self.EMAIL_AUTO_CONFIGURE:
                print("[EMAIL] Auto-configuration enabled - attempting to setup default email")
    
    def _validate_smtp_config(self):
        """Validate SMTP configuration details"""
        # Common SMTP port validation
        valid_ports = [25, 465, 587, 2525]
        if self.SMTP_PORT not in valid_ports:
            print(f"[EMAIL] WARNING: Unusual SMTP port: {self.SMTP_PORT}")
            print("[EMAIL] Common ports: 25 (SMTP), 465 (SMTPS), 587 (SMTP+TLS), 2525")
        
        # Gmail-specific validation
        if "gmail.com" in self.SMTP_HOST.lower():
            if self.SMTP_PORT != 587 and self.SMTP_PORT != 465:
                print("[EMAIL] WARNING: Gmail usually uses port 587 (TLS) or 465 (SSL)")
            print(f"[EMAIL] Port {self.SMTP_PORT} configured for Gmail - verifying TLS/SSL requirements")
            if self.SMTP_USE_TLS:
                print("[EMAIL] Email service configured with TLS - settings validated")
            else:
                print("[EMAIL] WARNING: Gmail requires TLS/SSL - SMTP_USE_TLS should be True")
    
    def validate_production(self):
        """Validate production-safe settings.

        In production (DEBUG=False) we no longer crash the app when SECRET_KEY
        is missing or still a placeholder. Instead we generate a strong
        ephemeral key and log clear warnings so the app continues to run
        without leaking any real secret in the codebase or repo.
        """
        if self.DEBUG:
            print("[INFO] Development mode enabled - production validations skipped")
            print("[INFO] WARNING: Remember to set DEBUG=False for production deployment")
            return

        # Production mode validations (non-fatal)
        placeholder_keys = {
            "CHANGE-THIS-SECRET-KEY-IN-PRODUCTION",
            "your-secret-key-change-in-production",
            "your-secret-key",
        }
        if "dev-secret-key" in self.SECRET_KEY.lower() or self.SECRET_KEY in placeholder_keys:
            print("[WARN] WARNING: PRODUCTION MODE but SECRET_KEY is still a placeholder.")
            print("[WARN] Generating a temporary SECRET_KEY for this process.")
            print("[WARN] For stable JWT tokens across restarts, set SECRET_KEY in .env or environment.")
            self.SECRET_KEY = secrets.token_urlsafe(32)

        if self.CORS_ORIGINS == ["*"]:
            print("[WARN] WARNING: CORS_ORIGINS set to wildcard in production. Consider restricting it.")

        print("[INFO] Production validations completed")
    
    def init_directories(self):
        """Create necessary directories"""
        try:
            self.DATA_ROOT.mkdir(exist_ok=True, parents=True)
            (self.DATA_ROOT / "tmp").mkdir(exist_ok=True, parents=True)
            (self.DATA_ROOT / "files").mkdir(exist_ok=True, parents=True)
            (self.DATA_ROOT / "avatars").mkdir(exist_ok=True, parents=True)
            print(f"[OK] Data directories initialized at {self.DATA_ROOT}")
        except Exception as e:
            print(f"[WARN] Failed to initialize directories: {str(e)}")
            print("[WARN] Continuing with startup - check file permissions if this is critical")


settings = Settings()

# Test email service on startup in DEBUG mode
if settings.DEBUG and False:
    print("[CONFIG] DEBUG mode enabled - testing email service...")
    settings.validate_email_config()
