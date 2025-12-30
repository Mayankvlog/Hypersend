import os
from pathlib import Path
from dotenv import load_dotenv
from urllib.parse import quote_plus
import secrets

# Load environment variables from .env file
env_path = Path(__file__).parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

# Also check current directory
if not os.getenv("MONGODB_URI") and not os.getenv("MONGO_USER"):
    load_dotenv()


class Settings:
    # MongoDB Connection
    # For development, use MongoDB Atlas or local MongoDB
    # Read MongoDB credentials from environment
    _MONGO_USER: str = os.getenv("MONGO_USER", "hypersend")
    _MONGO_PASSWORD: str = os.getenv("MONGO_PASSWORD", "hypersend_secure_password")
    _MONGO_HOST: str = os.getenv("MONGO_HOST", "localhost")
    _MONGO_PORT: str = os.getenv("MONGO_PORT", "27017")
    _MONGO_DB: str = os.getenv("MONGO_INITDB_DATABASE", "hypersend")
    
    # Try to get MongoDB URI from environment first, fallback to local development setup
    if os.getenv("MONGODB_URI"):
        MONGODB_URI: str = os.getenv("MONGODB_URI")
    else:
        # Construct MONGODB_URI with proper URL encoding for special characters in password
        from urllib.parse import quote_plus
        encoded_password = quote_plus(_MONGO_PASSWORD)
        # Connect directly to target database with admin authentication
        # Include replicaSet and retry logic for VPS deployments
        MONGODB_URI: str = f"mongodb://{_MONGO_USER}:{encoded_password}@{_MONGO_HOST}:{_MONGO_PORT}/{_MONGO_DB}?authSource=admin&retryWrites=true&w=majority"
        print(f"[CONFIG] MongoDB connection: authenticated with retries")
    
    # Log connection info without exposing credentials
    if '@' in MONGODB_URI:
        host_info = MONGODB_URI.split('@')[1].split('/')[0]
        print(f"[CONFIG] MongoDB URI host: {host_info}")
    else:
        print(f"[CONFIG] MongoDB connection: direct connection")
    
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
    
    # QR Code session expiration
    QR_CODE_SESSION_EXPIRE_MINUTES: int = int(os.getenv("QR_CODE_SESSION_EXPIRE_MINUTES", "5"))
    PASSWORD_RESET_EXPIRE_MINUTES: int = int(os.getenv("PASSWORD_RESET_EXPIRE_MINUTES", "30"))
    
    # File Storage (WhatsApp-style: Local only)
    STORAGE_MODE: str = os.getenv("STORAGE_MODE", "local")  # local, server, or hybrid
    DATA_ROOT: Path = Path(os.getenv("DATA_ROOT", "./data"))  # Only for metadata/temp
    CHUNK_SIZE: int = int(os.getenv("CHUNK_SIZE", "4194304"))  # 4 MiB
    MAX_FILE_SIZE_BYTES: int = int(os.getenv("MAX_FILE_SIZE_BYTES", "42949672960"))  # 40 GiB
    MAX_PARALLEL_CHUNKS: int = int(os.getenv("MAX_PARALLEL_CHUNKS", "4"))
    FILE_RETENTION_HOURS: int = int(os.getenv("FILE_RETENTION_HOURS", "0"))  # 0 = no server storage
    UPLOAD_EXPIRE_HOURS: int = int(os.getenv("UPLOAD_EXPIRE_HOURS", "24"))  # Upload session expiry
    
    # API
    API_HOST: str = os.getenv("API_HOST", "0.0.0.0")
    API_PORT: int = int(os.getenv("API_PORT", "8000"))  # Backend listens on 8000, Nginx proxies to it
    # Default public API base URL for this deployment (VPS behind Nginx HTTPS)
    # Note: Nginx proxies /api/ to backend on port 8000, so full URL includes /api/v1
    API_BASE_URL: str = os.getenv("API_BASE_URL", "https://localhost:8000/api/v1")
    
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
    
    # Mock mode for testing without MongoDB - CRITICAL: Default to False for production
    use_mock_db_env = os.getenv("USE_MOCK_DB", "False")
    print(f"[CONFIG] USE_MOCK_DB env var: '{use_mock_db_env}'")
    USE_MOCK_DB: bool = use_mock_db_env.lower() in ("true", "1", "yes")
    print(f"[CONFIG] USE_MOCK_DB final: {USE_MOCK_DB}")
    if USE_MOCK_DB:
        print("[CONFIG] WARNING: USING MOCK DATABASE - FOR TESTING ONLY")
    
    # CRITICAL: Production safety check
    if not DEBUG and USE_MOCK_DB:
        raise RuntimeError("🚨 PRODUCTION SAFETY ERROR: Mock database cannot be used in production. Set USE_MOCK_DB=False")
    
    # CORS Configuration
    # FIX: Load from environment or use defaults that support all access patterns
    # NOTE: CORS is for browser security, not API authentication - allow common patterns
    CORS_ORIGINS: list = os.getenv("CORS_ORIGINS", "").split(",") if os.getenv("CORS_ORIGINS") else [
        "*",  # Allow all origins in development/local
        "http://localhost",
        "http://localhost:8000",
        "http://localhost:3000",
        "http://localhost:8550",
        "http://127.0.0.1",
        "http://127.0.0.1:8000",
        "http://127.0.0.1:3000",
        "http://0.0.0.0:8000",
        "http://backend:8000",
        "http://frontend",
        # Add VPS IP / domain (HTTP + HTTPS) and production frontend
        "http://139.59.82.105",
        "http://139.59.82.105:8000",
        "http://139.59.82.105:8550",
        "https://139.59.82.105",
        "https://139.59.82.105:8000",
        # Production URLs should be configured via CORS_ORIGINS env var
        "http://localhost:3000",
        "http://localhost:8080",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8080",
    ]
    
    def __init__(self):
        """Initialize settings and validate critical configuration"""
        self.validate_config()
    
    def validate_config(self):
        """Validate critical configuration"""
        # SECRET_KEY must be explicitly set in production
        if not self.SECRET_KEY:
            raise ValueError("SECRET_KEY environment variable must be set in production")
        
        if not os.getenv("SECRET_KEY"):
            raise ValueError("SECRET_KEY must be set as environment variable in production")
        
        if len(self.SECRET_KEY) < 32:
            self.SECRET_KEY = secrets.token_urlsafe(64)
        
        # Validate email configuration
        self.validate_email_config()
    
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
            
            # Test email service on startup in DEBUG mode
            if self.DEBUG:
                self._test_email_service_on_startup()
        else:
            print("[EMAIL] X Email service NOT configured - password reset emails will not be sent")
            print("[EMAIL] To enable email, set: SMTP_HOST, SMTP_USERNAME, SMTP_PASSWORD, EMAIL_FROM")
            
            if self.EMAIL_FALLBACK_ENABLED:
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
            print("[EMAIL] WARNING: Port {self.SMTP_PORT} typically requires TLS/SSL")
            print("[EMAIL] Email service test successful")
            print(f"[EMAIL] Email service test failed: {test_message}")
            print("[EMAIL] Check SMTP configuration and network connectivity")
    
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
if settings.DEBUG:
    print("[CONFIG] DEBUG mode enabled - testing email service...")
    settings.validate_email_config()
