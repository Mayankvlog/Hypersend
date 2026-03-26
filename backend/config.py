import os
import sys
import logging
from pathlib import Path
from typing import List, Optional
from dotenv import load_dotenv
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
import secrets

# Setup logging FIRST
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# ============================================================================
# CENTRALIZED ENVIRONMENT LOADING - Single source of truth
# CRITICAL: Only load once to prevent duplicate initialization
# ============================================================================

_env_already_loaded = False


def _load_env_files():
    """Load environment files in production order (single load only)"""
    global _env_already_loaded

    if _env_already_loaded:
        return  # Already loaded, prevent duplicate

    # Search for .env in multiple locations
    _env_paths = [
        Path("/app/backend/.env"),
        Path("/app/.env"),
        Path("/app/backend/.env.production"),
        Path(__file__).parent.parent / ".env",  # Project root .env
        Path(__file__).parent / ".env",  # Backend directory .env
        Path.cwd() / ".env",  # Current working directory .env
    ]
    for env_path in _env_paths:
        if env_path.exists():
            logger.info(f"[CONFIG] Loading environment from {env_path}")
            load_dotenv(dotenv_path=env_path, override=False)
            _env_already_loaded = True
            return

    logger.debug("[CONFIG] No .env files found, using environment variables only")
    _env_already_loaded = True


_load_env_files()

# simple flag used throughout Settings to relax strict production requirements
# when running under pytest or in a testing environment. Checking for the
# presence of the pytest module is reliable because pytest imports itself
# before it begins collecting test modules (including backend.*), so this
# variable will be True at import time when tests are executing.
TESTING = bool(os.getenv("PYTEST_CURRENT_TEST")) or "pytest" in sys.modules


def _strip_quotes(value: str) -> str:
    """Safely strip quotes from environment variable values"""
    if not value:
        return value
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]
    return value


def _sanitize_s3_bucket(value: str) -> str:
    if value is None:
        return ""
    value = _strip_quotes(str(value)).strip()
    if value.startswith("arn:aws:s3:::"):
        value = value.replace("arn:aws:s3:::", "")
    return value


def _validate_s3_bucket(value: str) -> str:
    """Validate S3 bucket name (not ARN, non-empty, basic DNS rules)."""
    value = _sanitize_s3_bucket(value)
    if not value:
        return ""
    # Basic S3 bucket naming rules (not exhaustive)
    import re

    if len(value) < 3 or len(value) > 63:
        raise ValueError("S3_BUCKET must be 3-63 characters")
    if not re.fullmatch(r"[a-z0-9][a-z0-9\.-]*[a-z0-9]", value):
        raise ValueError("S3_BUCKET contains invalid characters")
    if ".." in value or ".-" in value or "-." in value:
        raise ValueError("S3_BUCKET has invalid dot/dash sequence")
    if value.startswith(".") or value.endswith("."):
        raise ValueError("S3_BUCKET cannot start/end with '.'")
    return value


def _sanitize_aws_region(value: str) -> str:
    if value is None:
        return ""
    return _strip_quotes(str(value)).strip()


def _validate_mongodb_uri(uri: str) -> str:
    """Validate and enforce MongoDB Atlas URI (mongodb+srv:// only)"""
    uri = uri.strip()

    # Strip quotes if present
    uri = _strip_quotes(uri)

    # CRITICAL: Only allow mongodb+srv:// URIs - no localhost, no mongodb://
    if not uri.startswith("mongodb+srv://"):
        raise RuntimeError(
            f"MONGODB_URI must be Atlas URI starting with 'mongodb+srv://'. Got: {uri[:60]}..."
        )

    # Parse URI to check and auto-append missing parameters
    parsed = urlparse(uri)
    query_params = parse_qs(parsed.query)

    # Auto-append missing critical parameters
    requires_fix = False
    if "retryWrites" not in query_params:
        query_params["retryWrites"] = ["true"]
        requires_fix = True
    if "w" not in query_params:
        query_params["w"] = ["majority"]
        requires_fix = True

    if requires_fix:
        # Reconstruct query string
        new_query = urlencode({k: v[0] for k, v in query_params.items()}, safe="")
        uri = urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment,
            )
        )
        logger.info(
            "[CONFIG] MongoDB Atlas URI auto-fixed with retryWrites=true and w=majority"
        )

    return uri


def _mask_mongodb_uri(uri: str) -> str:
    """Mask password in MongoDB URI for logging"""
    try:
        if "@" not in uri:
            return uri
        prefix = uri.split("@")[0]
        suffix = uri.split("@")[1]
        # Hide password in prefix
        if "://" in prefix:
            scheme_part = prefix.split("://")[0]
            return f"{scheme_part}://***:***@{suffix}"
        return uri
    except Exception:
        return "***MASKED***"


class Settings:
    # ============================================================================
    # MONGODB ATLAS CONFIGURATION - Production only, no local fallback
    # ============================================================================

    # Load raw values with validation
    _raw_mongodb_uri = os.getenv("MONGODB_URI")
    _raw_database_name = os.getenv("DATABASE_NAME")
    _raw_atlas_enabled = os.getenv("MONGODB_ATLAS_ENABLED", "true").lower() in ("true", "1", "yes")

    # CRITICAL: Enforce mock database disabled globally (never allowed)
    _use_mock_db = os.getenv("USE_MOCK_DB", "false").lower() in ("true", "1", "yes")
    if _use_mock_db:
        logger.error("[CONFIG] CRITICAL: USE_MOCK_DB is permanently disabled")
        raise RuntimeError(
            "CRITICAL: USE_MOCK_DB must be 'false' - mock database is permanently disabled"
        )

    # Validate MongoDB Atlas configuration is present (required)
    if not _raw_mongodb_uri:
        raise RuntimeError(
            "CRITICAL: MONGODB_URI is required for MongoDB Atlas deployment. "
            "Format: mongodb+srv://user:password@cluster.mongodb.net/db?retryWrites=true&w=majority"
        )

    if not _raw_database_name:
        raise RuntimeError("CRITICAL: DATABASE_NAME is required for MongoDB Atlas.")

    if not _raw_atlas_enabled:
        raise RuntimeError(
            "CRITICAL: MONGODB_ATLAS_ENABLED must be 'true' for MongoDB Atlas only."
        )

    # Validate and auto-fix URI
    MONGODB_URI: str = _validate_mongodb_uri(_raw_mongodb_uri)
    DATABASE_NAME: str = _raw_database_name.strip()
    MONGODB_ATLAS_ENABLED: bool = _raw_atlas_enabled

    logger.info(
        f"[CONFIG] MongoDB Atlas configured: {_mask_mongodb_uri(MONGODB_URI)} -> {DATABASE_NAME}"
    )

    # ============================================================================
    # DEVELOPMENT CONFIGURATION
    # ============================================================================

    # ============================================================================
    # SECURITY CONFIGURATION
    # ============================================================================

    # JWT and SECRET keys - REQUIRED in production
    _env_jwt_secret = _strip_quotes(os.getenv("JWT_SECRET_KEY", "")).strip()
    _env_secret = _strip_quotes(os.getenv("SECRET_KEY", "")).strip()

    if not (_env_jwt_secret or _env_secret) and not TESTING:
        raise ValueError(
            "CRITICAL: JWT_SECRET_KEY or SECRET_KEY must be set in production"
        )

    JWT_SECRET_KEY: str = _env_jwt_secret or _env_secret
    SECRET_KEY: str = JWT_SECRET_KEY
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")

    # Token expiration constants
    # SESSION_DURATION must equal exactly 20 days (1,728,000 seconds)
    SESSION_DURATION_DAYS: int = 20  # Production requirement: exactly 20 days
    SESSION_DURATION_SECONDS: int = 1728000  # 20 days in seconds (86400 * 20)

    # CRITICAL FIX: Access token must be valid for entire 20-day session
    # Default to 20 days (28,800 minutes) to match session duration requirement
    # This was incorrectly set to 15 minutes - now fixed to 20 days
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(
        os.getenv(
            "ACCESS_TOKEN_EXPIRE_MINUTES", "28800"
        )  # Changed from "15" to "28800" (20 days in minutes)
    )
    # Convert to seconds for cookie Max-Age calculations
    ACCESS_TOKEN_EXPIRE_SECONDS: int = (
        ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )  # Should equal 1,728,000 seconds

    # CRITICAL: Refresh token expiration must be 20 days (production requirement)
    # Users must be able to maintain sessions for exactly 20 days before re-authentication
    REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "20"))
    REFRESH_TOKEN_EXPIRE_SECONDS: int = (
        REFRESH_TOKEN_EXPIRE_DAYS * 86400
    )  # 1,728,000 seconds
    UPLOAD_TOKEN_EXPIRE_HOURS: int = int(
        os.getenv("UPLOAD_TOKEN_EXPIRE_HOURS", "480")
    )  # Extended tokens for large uploads
    UPLOAD_TOKEN_DURATION: int = UPLOAD_TOKEN_EXPIRE_HOURS * 3600

    # QR Code session expiration
    QR_CODE_SESSION_EXPIRE_MINUTES: int = int(
        os.getenv("QR_CODE_SESSION_EXPIRE_MINUTES", "5")
    )
    PASSWORD_RESET_EXPIRE_MINUTES: int = int(
        os.getenv("PASSWORD_RESET_EXPIRE_MINUTES", "30")
    )

    # File Storage
    STORAGE_MODE: str = os.getenv("STORAGE_MODE", "local")
    DATA_ROOT: Path = Path(os.getenv("DATA_ROOT", "/app/data"))
    TEMP_STORAGE_PATH: str = os.getenv("TEMP_STORAGE_PATH", "/app/temp")
    UPLOAD_DIR: str = os.getenv("UPLOAD_DIR", "/app/uploads")
    SERVER_STORAGE_ENABLED: bool = os.getenv(
        "SERVER_STORAGE_ENABLED", "true"
    ).lower() in (
        "true",
        "1",
        "yes",
    )
    CHUNK_SIZE: int = int(os.getenv("CHUNK_SIZE", "4194304"))  # 4 MiB
    UPLOAD_CHUNK_SIZE: int = CHUNK_SIZE
    MAX_FILE_SIZE_BYTES: int = int(
        os.getenv("MAX_FILE_SIZE_BYTES", "16106127360")
    )  # 15 GiB
    USER_QUOTA_BYTES: int = int(
        os.getenv("USER_QUOTA_BYTES", str(10 * 1024 * 1024 * 1024))
    )  # 10 GB default
    MAX_PARALLEL_CHUNKS: int = int(os.getenv("MAX_PARALLEL_CHUNKS", "4"))
    _raw_file_retention = int(
        os.getenv("FILE_RETENTION_HOURS", "120")
    )  # 120 hours - 5 days default
    # CRITICAL: Allow FILE_RETENTION_HOURS to be set via environment
    # If set to 0 or negative, default to 120 hours
    FILE_RETENTION_HOURS: int = 120 if _raw_file_retention <= 0 else _raw_file_retention

    # CENTRALIZED FILE TTL - Single source of truth based on FILE_RETENTION_HOURS
    # CRITICAL: All file expiry uses this dynamically calculated value
    FILE_TTL_SECONDS: int = FILE_RETENTION_HOURS * 3600  # Convert hours to seconds
    FILE_TTL_HOURS: int = FILE_RETENTION_HOURS  # Use configured value directly

    # Automatic file cleanup configuration
    AUTO_CLEANUP_ENABLED: bool = os.getenv("AUTO_CLEANUP_ENABLED", "true").lower() in (
        "true",
        "1",
        "yes",
    )
    FILE_CLEANUP_INTERVAL_MINUTES: int = int(
        os.getenv("FILE_CLEANUP_INTERVAL_MINUTES", "60")
    )  # Run cleanup every 60 minutes

    logger.info(f"[CONFIG] File Retention: {FILE_RETENTION_HOURS} hours")
    logger.info(
        f"[CONFIG] Centralized File TTL: {FILE_TTL_SECONDS} seconds ({FILE_TTL_HOURS} hours)"
    )
    logger.info(
        f"[CONFIG] Auto Cleanup: {'Enabled' if AUTO_CLEANUP_ENABLED else 'Disabled'} (interval: {FILE_CLEANUP_INTERVAL_MINUTES}min)"
    )

    # Enhanced timeout settings for large file transfers
    CHUNK_UPLOAD_TIMEOUT_SECONDS: int = int(
        os.getenv("CHUNK_UPLOAD_TIMEOUT_SECONDS", "600")
    )  # 10 minutes per chunk (for 15GB files)
    FILE_ASSEMBLY_TIMEOUT_MINUTES: int = int(
        os.getenv("FILE_ASSEMBLY_TIMEOUT_MINUTES", "30")
    )  # 30 minutes for assembly (15GB)
    MAX_UPLOAD_RETRY_ATTEMPTS: int = int(
        os.getenv("MAX_UPLOAD_RETRY_ATTEMPTS", "7")
    )  # More retries for large files

    # Large file handling optimizations
    LARGE_FILE_THRESHOLD_GB: int = int(
        os.getenv("LARGE_FILE_THRESHOLD_GB", "1")
    )  # Files > 1GB get special handling
    LARGE_FILE_THRESHOLD: int = LARGE_FILE_THRESHOLD_GB * 1024 * 1024 * 1024
    LARGE_FILE_CHUNK_TIMEOUT_SECONDS: int = int(
        os.getenv("LARGE_FILE_CHUNK_TIMEOUT_SECONDS", "900")
    )  # 15 minutes for large file chunks

    # Upload token durations
    UPLOAD_TOKEN_DURATION_LARGE: int = int(
        os.getenv("UPLOAD_TOKEN_DURATION_LARGE", str(UPLOAD_TOKEN_DURATION))
    )

    # API
    API_HOST: str = os.getenv("API_HOST", "0.0.0.0")
    API_PORT: int = int(
        os.getenv("API_PORT", "8000")
    )  # Backend listens on 8000, Nginx proxies to it
    # Production API base URL - must use HTTPS domain
    API_BASE_URL: str = os.getenv("API_BASE_URL", "https://zaply.in.net/api/v1")

    # Rate Limiting
    RATE_LIMIT_PER_USER: int = int(os.getenv("RATE_LIMIT_PER_USER", "100"))
    RATE_LIMIT_WINDOW_SECONDS: int = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))

    # Email / SMTP (optional - used for password reset emails)
    SMTP_HOST: str = os.getenv("SMTP_HOST", "")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USERNAME: str = os.getenv("SMTP_USERNAME", "")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
    SMTP_USE_TLS: bool = os.getenv("SMTP_USE_TLS", "True").lower() in (
        "true",
        "1",
        "yes",
    )
    EMAIL_FROM: str = os.getenv("EMAIL_FROM", "")

    # ============================================================================
    # REDIS CONFIGURATION - Docker service name only, NO localhost
    # ============================================================================

    _raw_redis_host = os.getenv("REDIS_HOST", "redis").strip()
    if _raw_redis_host in ("localhost", "127.0.0.1", "::1"):
        logger.error(
            "[CONFIG] CRITICAL: REDIS_HOST cannot be localhost in production - forcing to 'redis'"
        )
        _raw_redis_host = "redis"

    REDIS_HOST: str = _raw_redis_host
    REDIS_PORT: int = int(os.getenv("REDIS_PORT", "6379"))
    REDIS_PASSWORD: str = os.getenv("REDIS_PASSWORD", "").strip()
    REDIS_DB: int = int(os.getenv("REDIS_DB", "0"))

    # CRITICAL SECURITY FIX: Build REDIS_URL with password authentication
    # Format: redis://:password@host:port/db (password is required in production)
    # CRITICAL: Use docker service name 'redis', never localhost
    if REDIS_PASSWORD:
        # URL with authentication - CRITICAL for production
        _redis_url_default = (
            f"redis://:{REDIS_PASSWORD}@{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}"
        )
    else:
        # URL without authentication (development only)
        _redis_url_default = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}"

    # Get REDIS_URL from environment, falling back to constructed URL
    REDIS_URL: str = os.getenv("REDIS_URL", _redis_url_default).strip()

    # CRITICAL: Validate and fix Redis URL format for production
    if "localhost" in REDIS_URL or "127.0.0.1" in REDIS_URL:
        logger.error(
            "[CONFIG] CRITICAL: REDIS_URL contains localhost - forcing to docker service name"
        )
        REDIS_URL = REDIS_URL.replace("localhost", "redis").replace(
            "127.0.0.1", "redis"
        )
        logger.info(f"[CONFIG] Fixed REDIS_URL: {REDIS_URL}")

    # CRITICAL: Verify REDIS_URL includes password if REDIS_PASSWORD is set
    if REDIS_PASSWORD and f":{REDIS_PASSWORD}@" not in REDIS_URL:
        logger.error(
            "[CONFIG] CRITICAL: REDIS_URL does not include password - reconstructing with auth"
        )
        REDIS_URL = f"redis://:{REDIS_PASSWORD}@{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}"
        logger.info(f"[CONFIG] Reconstructed REDIS_URL with authentication")

    logger.info(
        f"[CONFIG] Redis configured: {REDIS_HOST}:{REDIS_PORT}/db{REDIS_DB} (with password: {bool(REDIS_PASSWORD)})"
    )
    # WHATSAPP MESSAGE STORAGE: Redis is ONLY temporary store
    MESSAGE_STORAGE: str = os.getenv(
        "MESSAGE_STORAGE", "redis_only"
    )  # redis_only = WhatsApp style
    MESSAGE_TTL_MINUTES: int = int(
        os.getenv("MESSAGE_TTL_MINUTES", "60")
    )  # Messages expire after 1 hour
    MESSAGE_TTL_SECONDS: int = MESSAGE_TTL_MINUTES * 60  # Convert to seconds for Redis
    # CRITICAL: Messages older than TTL are DELETED (acceptable, user device has backup)
    REDIS_MAX_CONNECTIONS: int = int(os.getenv("REDIS_MAX_CONNECTIONS", "100"))
    REDIS_SOCKET_TIMEOUT: int = int(os.getenv("REDIS_SOCKET_TIMEOUT", "5"))
    REDIS_SOCKET_CONNECT_TIMEOUT: int = int(
        os.getenv("REDIS_SOCKET_CONNECT_TIMEOUT", "5")
    )
    REDIS_MAX_MEMORY: str = os.getenv(
        "REDIS_MAX_MEMORY", "2gb"
    )  # 2GB for ephemeral messages

    # Email service validation with enhanced checking
    EMAIL_SERVICE_ENABLED: bool = bool(
        SMTP_HOST and SMTP_USERNAME and SMTP_PASSWORD and EMAIL_FROM
    )

    # Email rate limiting (prevent spam)
    EMAIL_RATE_LIMIT_PER_HOUR: int = int(os.getenv("EMAIL_RATE_LIMIT_PER_HOUR", "10"))
    EMAIL_RATE_LIMIT_PER_DAY: int = int(os.getenv("EMAIL_RATE_LIMIT_PER_DAY", "50"))

    # Email service auto-configuration for development
    EMAIL_AUTO_CONFIGURE: bool = os.getenv("EMAIL_AUTO_CONFIGURE", "False").lower() in (
        "true",
        "1",
        "yes",
    )

    # Fallback email configuration for development
    EMAIL_FALLBACK_ENABLED: bool = os.getenv(
        "EMAIL_FALLBACK_ENABLED", "True"
    ).lower() in ("true", "1", "yes")

    # Development
    # Default DEBUG to True for development; set to False in production with proper SECRET_KEY
    DEBUG: bool = os.getenv("DEBUG", "True").lower() in ("true", "1", "yes")

    # SSL Certificate Validation (defined after DEBUG)
    # CRITICAL: Controls whether to verify SSL certificates for external API calls
    # Development: Can be disabled for self-signed certificates
    # Production: MUST be True for security
    VERIFY_SSL_CERTIFICATES: bool = os.getenv(
        "VERIFY_SSL_CERTIFICATES", "False"
    ).lower() in ("true", "1", "yes")

    # SSL Certificate Bundle Path (for custom CA certificates)
    # Leave empty to use system default certificates
    SSL_CERT_BUNDLE: str = os.getenv("SSL_CERT_BUNDLE", "")

    # SSL Certificate Verification Mode
    # Options: "strict" (verify all), "relaxed" (allow self-signed in dev), "disabled" (no verification)
    SSL_VERIFY_MODE: str = os.getenv(
        "SSL_VERIFY_MODE", "relaxed" if DEBUG else "strict"
    )

    # Email / SMTP (optional - used for password reset emails)
    ENABLE_PASSWORD_RESET: bool = os.getenv(
        "ENABLE_PASSWORD_RESET", "True"
    ).lower() in ("true", "1", "yes")
    ENABLE_EMAIL: bool = os.getenv("ENABLE_EMAIL", "True").lower() in (
        "true",
        "1",
        "yes",
    )

    # ============================================================================
    # AWS/S3 CONFIGURATION (optional for WhatsApp model)
    # ============================================================================
    # CRITICAL: AWS credentials are loaded from environment variables only
    # Never hardcode credentials - use .env file or deployment secrets

    _raw_s3_bucket = _sanitize_s3_bucket(os.getenv("S3_BUCKET", ""))
    # IMPORTANT: Do not silently default bucket in backend.
    # Empty means "not configured" and should be validated at the call sites.
    S3_BUCKET: str = _validate_s3_bucket(_raw_s3_bucket) if _raw_s3_bucket else ""
    AWS_ACCESS_KEY_ID: str = _strip_quotes(os.getenv("AWS_ACCESS_KEY_ID", "")).strip()
    AWS_SECRET_ACCESS_KEY: str = _strip_quotes(
        os.getenv("AWS_SECRET_ACCESS_KEY", "")
    ).strip()
    AWS_REGION: str = (
        _sanitize_aws_region(os.getenv("AWS_REGION", "us-east-1")) or "us-east-1"
    )

    # Helper: Check if AWS credentials are configured
    _AWS_CREDENTIALS_CONFIGURED: bool = bool(
        AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY
    )

    # ============================================================================
    # STORAGE MODEL CONFIGURATION
    # ============================================================================

    WHATSAPP_STORAGE: bool = os.getenv("WHATSAPP_STORAGE", "true").lower() in (
        "true",
        "1",
        "yes",
    )
    USER_DEVICE_ONLY: bool = os.getenv("USER_DEVICE_ONLY", "true").lower() in (
        "true",
        "1",
        "yes",
    )
    NO_SERVER_MEDIA: bool = os.getenv("NO_SERVER_MEDIA", "true").lower() in (
        "true",
        "1",
        "yes",
    )
    USER_DEVICE_STORAGE: bool = os.getenv("USER_DEVICE_STORAGE", "true").lower() in (
        "true",
        "1",
        "yes",
    )
    COST_MODEL: str = os.getenv("COST_MODEL", "free")
    MAX_STORAGE_PER_USER_GB: int = int(os.getenv("MAX_STORAGE_PER_USER_GB", "0"))
    SERVER_STORAGE_BYTES: int = int(os.getenv("SERVER_STORAGE_BYTES", "0"))

    # Backward compatibility paths
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

    # 15GB Maximum File Size Support
    MAX_FILE_SIZE_MB: int = int(os.getenv("MAX_FILE_SIZE_MB", "15360"))  # 15GB in MB
    MAX_FILE_SIZE_BYTES: int = int(
        os.getenv("MAX_FILE_SIZE_BYTES", str(15 * 1024 * 1024 * 1024))
    )  # 15GB in bytes
    LARGE_FILE_THRESHOLD_GB: int = int(
        os.getenv("LARGE_FILE_THRESHOLD_GB", "1")
    )  # 1GB threshold
    LARGE_FILE_THRESHOLD: int = LARGE_FILE_THRESHOLD_GB * 1024 * 1024 * 1024

    # WhatsApp-like File Type Limits (Updated for 15GB support)
    MAX_IMAGE_SIZE_MB: int = int(
        os.getenv("MAX_IMAGE_SIZE_MB", "4096")
    )  # 4GB for high-res images
    MAX_VIDEO_SIZE_MB: int = int(
        os.getenv("MAX_VIDEO_SIZE_MB", "15360")
    )  # 15GB for videos
    MAX_AUDIO_SIZE_MB: int = int(
        os.getenv("MAX_AUDIO_SIZE_MB", "2048")
    )  # 2GB for audio
    MAX_DOCUMENT_SIZE_MB: int = int(
        os.getenv("MAX_DOCUMENT_SIZE_MB", "15360")
    )  # 15GB for documents

    # Convert to bytes
    MAX_IMAGE_SIZE_BYTES: int = MAX_IMAGE_SIZE_MB * 1024 * 1024
    MAX_VIDEO_SIZE_BYTES: int = MAX_VIDEO_SIZE_MB * 1024 * 1024
    MAX_AUDIO_SIZE_BYTES: int = MAX_AUDIO_SIZE_MB * 1024 * 1024
    MAX_DOCUMENT_SIZE_BYTES: int = MAX_DOCUMENT_SIZE_MB * 1024 * 1024

    # WhatsApp-like Supported File Types
    SUPPORTED_IMAGE_TYPES: list = os.getenv(
        "SUPPORTED_IMAGE_TYPES", "jpg,jpeg,png,gif,webp,bmp,heic,heif"
    ).split(",")
    SUPPORTED_VIDEO_TYPES: list = os.getenv(
        "SUPPORTED_VIDEO_TYPES", "mp4,mov,avi,mkv,webm,3gp,m4v"
    ).split(",")
    SUPPORTED_AUDIO_TYPES: list = os.getenv(
        "SUPPORTED_AUDIO_TYPES", "mp3,wav,aac,m4a,ogg,flac,amr"
    ).split(",")
    SUPPORTED_DOCUMENT_TYPES: list = os.getenv(
        "SUPPORTED_DOCUMENT_TYPES", "pdf,doc,docx,xls,xlsx,ppt,pptx,txt,rtf,zip,rar"
    ).split(",")

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
        "upload": UPLOADS_PATH,
    }

    # ============================================================================
    # LOGGING: AWS/S3 CONFIGURATION STATUS
    # ============================================================================
    logger.info(f"[CONFIG] S3 Bucket: {S3_BUCKET}")
    logger.info(f"[CONFIG] AWS Region: {AWS_REGION}")

    # VALIDATE S3 CONFIGURATION - Log bucket status
    if not _raw_s3_bucket:
        logger.warning(
            "[CONFIG] S3_BUCKET not set (uploads requiring S3 will fail until configured)"
        )
    else:
        logger.info(f"[CONFIG] S3_BUCKET configured: {S3_BUCKET}")

    # Log AWS credential status (without exposing secrets)
    if _AWS_CREDENTIALS_CONFIGURED:
        # Mask credential keys for logging
        masked_key_id = (
            AWS_ACCESS_KEY_ID[:4] + "***" if len(AWS_ACCESS_KEY_ID) > 4 else "***"
        )
        logger.info(
            f"[CONFIG] AWS Credentials: ✓ Configured (Key ID: {masked_key_id}...)"
        )
    else:
        logger.warning(
            "[CONFIG] AWS Credentials: Not configured - will use IAM role or boto3 default provider chain"
        )

    logger.info(
        "[CONFIG] S3/Media Access: Use /api/v1/media/{file_key} endpoint - no direct S3 URLs exposed"
    )

    # File upload settings (15GB Support)
    # LARGE_FILE_THRESHOLD and MAX_FILE_SIZE already set above
    # Remove duplicate assignments to avoid conflicts

    # CORS Configuration
    # DEVELOPMENT: Use localhost for local testing
    cors_origins_default = [
        "https://zaply.in.net",
        "https://www.zaply.in.net",
    ]

    CORS_ORIGINS = cors_origins_default

    # Production domain for token validation
    PRODUCTION_DOMAIN: str = "zaply.in.net"
    ALLOWED_FRONTEND_ORIGINS: List[str] = cors_origins_default

    def __init__(self):
        # Strict production CORS policy: ignore env overrides to prevent accidental non-production origins.
        self.CORS_ORIGINS = list(self.cors_origins_default)
        self.PRODUCTION_DOMAIN = "zaply.in.net"
        self.ALLOWED_FRONTEND_ORIGINS = list(self.cors_origins_default)

        # CRITICAL: Initialize storage directories at startup, before any routes load
        # This ensures storage is available before the first request
        self.init_directories()
        self.validate_storage_paths()

    # NOTE: CORS origins should be configured per environment - NEVER use wildcard "*" in production
    def _get_cors_origins(self) -> list:
        """Get CORS origins based on environment"""
        return list(self.cors_origins_default)

    def validate_email_config(self):
        """Validate email service configuration with enhanced checking"""
        if self.EMAIL_SERVICE_ENABLED:
            logger.info(f"[EMAIL] Email service configured with host: {self.SMTP_HOST}")
            logger.info(f"[EMAIL] Email from: {self.EMAIL_FROM}")
            logger.info(
                f"[EMAIL] Rate limits: {self.EMAIL_RATE_LIMIT_PER_HOUR}/hour, {self.EMAIL_RATE_LIMIT_PER_DAY}/day"
            )

            # Enhanced email format validation
            if "@" not in self.EMAIL_FROM or "." not in self.EMAIL_FROM.split("@")[1]:
                logger.warning(
                    f"[EMAIL] WARNING: Invalid email format: {self.EMAIL_FROM}"
                )

            # Validate SMTP configuration
            self._validate_smtp_config()

            logger.info("[EMAIL] Email service ready for use")
        else:
            # Only show email warning in debug mode to reduce log noise in production
            if self.DEBUG:
                logger.info(
                    "[EMAIL] Email service NOT configured - password reset emails will not be sent"
                )
                logger.info(
                    "[EMAIL] To enable email, set: SMTP_HOST, SMTP_USERNAME, SMTP_PASSWORD, EMAIL_FROM"
                )
            else:
                logger.info(
                    "[EMAIL] Email service disabled (optional - configure SMTP for password reset)"
                )

            if self.EMAIL_FALLBACK_ENABLED and self.DEBUG:
                logger.info(
                    "[EMAIL] Fallback mode: Tokens returned in debug mode for testing"
                )

            if self.EMAIL_AUTO_CONFIGURE:
                logger.info(
                    "[EMAIL] Auto-configuration enabled - attempting to setup default email"
                )

    def _validate_smtp_config(self):
        """Validate SMTP configuration details"""
        # Common SMTP port validation
        valid_ports = [25, 465, 587, 2525]
        if self.SMTP_PORT not in valid_ports:
            logger.warning(f"[EMAIL] WARNING: Unusual SMTP port: {self.SMTP_PORT}")
            logger.warning(
                "[EMAIL] Common ports: 25 (SMTP), 465 (SMTPS), 587 (SMTP+TLS), 2525"
            )

        # Gmail-specific validation
        if "gmail.com" in self.SMTP_HOST.lower():
            if self.SMTP_PORT != 587 and self.SMTP_PORT != 465:
                logger.warning(
                    "[EMAIL] WARNING: Gmail usually uses port 587 (TLS) or 465 (SSL)"
                )
            logger.info(
                f"[EMAIL] Port {self.SMTP_PORT} configured for Gmail - verifying TLS/SSL requirements"
            )
            if self.SMTP_USE_TLS:
                logger.info(
                    "[EMAIL] Email service configured with TLS - settings validated"
                )
            else:
                logger.warning(
                    "[EMAIL] WARNING: Gmail requires TLS/SSL - SMTP_USE_TLS should be True"
                )

    def validate_production(self):
        """Validate production-safe settings.

        In production (DEBUG=False) we no longer crash the app when SECRET_KEY
        is missing or still a placeholder. Instead we generate a strong
        ephemeral key and log clear warnings so the app continues to run
        without leaking any real secret in the codebase or repo.
        """
        if self.DEBUG:
            logger.info(
                "[INFO] Development mode enabled - production validations skipped"
            )
            logger.warning(
                "[INFO] WARNING: Remember to set DEBUG=False for production deployment"
            )
            return

        # Production mode validations (non-fatal)
        placeholder_keys = {
            "CHANGE-THIS-SECRET-KEY-IN-PRODUCTION",
            "your-secret-key-change-in-production",
            "your-secret-key",
        }
        if (
            "dev-secret-key" in self.SECRET_KEY.lower()
            or self.SECRET_KEY in placeholder_keys
        ):
            logger.warning(
                "[WARN] WARNING: PRODUCTION MODE but SECRET_KEY is still a placeholder."
            )
            logger.warning("[WARN] Generating a temporary SECRET_KEY for this process.")
            logger.warning(
                "[WARN] For stable JWT tokens across restarts, set SECRET_KEY in .env or environment."
            )
            self.SECRET_KEY = secrets.token_urlsafe(32)

        if self.CORS_ORIGINS == ["*"]:
            logger.warning(
                "[WARN] WARNING: CORS_ORIGINS set to wildcard in production. Consider restricting it."
            )

        logger.info("[INFO] Production validations completed")

    def validate_storage_paths(self):
        """Validate storage paths are writable and log configuration"""
        logger.info(f"[STORAGE] Validating storage configuration...")
        logger.info(f"[STORAGE] SERVER_STORAGE_ENABLED: {self.SERVER_STORAGE_ENABLED}")
        logger.info(f"[STORAGE] TEMP_STORAGE_PATH: {self.TEMP_STORAGE_PATH}")
        logger.info(f"[STORAGE] UPLOAD_DIR: {self.UPLOAD_DIR}")

        # Validate environment variable reading
        if not os.getenv("TEMP_STORAGE_PATH"):
            logger.warning(
                f"TEMP_STORAGE_PATH not in environment, using default: {self.TEMP_STORAGE_PATH}"
            )
        if not os.getenv("UPLOAD_DIR"):
            logger.warning(
                f"UPLOAD_DIR not in environment, using default: {self.UPLOAD_DIR}"
            )

        # Validate paths exist and are writable
        storage_paths = [
            ("TEMP_STORAGE_PATH", self.TEMP_STORAGE_PATH),
            ("UPLOAD_DIR", self.UPLOAD_DIR),
            ("DATA_ROOT", str(self.DATA_ROOT)),
        ]

        for path_name, path_str in storage_paths:
            path_obj = Path(path_str)
            if not path_obj.exists():
                logger.warning(f"[WARN] {path_name} does not exist: {path_str}")
            else:
                # Check if writable
                try:
                    # Try to create a temp file to test writability
                    test_file = path_obj / ".write_test"
                    test_file.touch(exist_ok=True)
                    test_file.unlink(missing_ok=True)
                    logger.info(f"[OK] {path_name} is writable: {path_str}")
                except Exception as e:
                    logger.error(
                        f"[ERROR] {path_name} is not writable: {path_str} - {type(e).__name__}: {str(e)}"
                    )

    def init_directories(self):
        """Create necessary directories - CRITICAL: called at Settings initialization"""
        try:
            self.DATA_ROOT.mkdir(exist_ok=True, parents=True)
            os.makedirs(self.TEMP_STORAGE_PATH, exist_ok=True)
            os.makedirs(self.UPLOAD_DIR, exist_ok=True)
            (self.DATA_ROOT / "files").mkdir(exist_ok=True, parents=True)
            (self.DATA_ROOT / "avatars").mkdir(exist_ok=True, parents=True)
            logger.info(f"Data directories initialized:")
            logger.info(f"  - DATA_ROOT: {self.DATA_ROOT}")
            logger.info(f"  - TEMP_STORAGE_PATH: {self.TEMP_STORAGE_PATH}")
            logger.info(f"  - UPLOAD_DIR: {self.UPLOAD_DIR}")
        except PermissionError as e:
            logger.error(f"Storage initialization FAILED - Permission denied: {str(e)}")
            logger.error(f"Backend must have write permission to storage directories")
            raise RuntimeError(f"Storage permission error: {str(e)}")
        except Exception as e:
            logger.error(
                f"Failed to initialize directories: {type(e).__name__}: {str(e)}"
            )
            import traceback

            logger.error(f"Traceback: {traceback.format_exc()}")
            raise RuntimeError(f"Storage initialization error: {str(e)}")


settings = Settings()

# Test email service on startup in DEBUG mode
if settings.DEBUG and False:
    logger.info("[CONFIG] DEBUG mode enabled - testing email service...")
    settings.validate_email_config()
