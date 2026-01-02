import os
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
    UPLOAD_DIR: str = os.getenv("UPLOAD_DIR", "./uploads")  # Upload directory for chunks
    CHUNK_SIZE: int = int(os.getenv("CHUNK_SIZE", "4194304"))  # 4 MiB
    MAX_FILE_SIZE_BYTES: int = int(os.getenv("MAX_FILE_SIZE_BYTES", "42949672960"))  # 40 GiB
    MAX_PARALLEL_CHUNKS: int = int(os.getenv("MAX_PARALLEL_CHUNKS", "4"))
    FILE_RETENTION_HOURS: int = int(os.getenv("FILE_RETENTION_HOURS", "0"))  # 0 = no server storage
    UPLOAD_EXPIRE_HOURS: int = int(os.getenv("UPLOAD_EXPIRE_HOURS", "48"))  # Extended to 48 hours for large files
    
    # Enhanced timeout settings for large file transfers
    CHUNK_UPLOAD_TIMEOUT_SECONDS: int = int(os.getenv("CHUNK_UPLOAD_TIMEOUT_SECONDS", "300"))  # 5 minutes per chunk
    FILE_ASSEMBLY_TIMEOUT_MINUTES: int = int(os.getenv("FILE_ASSEMBLY_TIMEOUT_MINUTES", "10"))  # 10 minutes for assembly
    MAX_UPLOAD_RETRY_ATTEMPTS: int = int(os.getenv("MAX_UPLOAD_RETRY_ATTEMPTS", "3"))  # Retry failed chunks
    
    # API
    API_HOST: str = os.getenv("API_HOST", "0.0.0.0")
    API_PORT: int = int(os.getenv("API_PORT", "8000"))  # Backend listens on 8000, Nginx proxies to it
    # Default public API base URL for this deployment
    # PROD: https://zaply.in.net/api/v1 (requires DNS + SSL setup)
    # DEV: Set API_BASE_URL=http://localhost:8080/api/v1 in docker-compose
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
        raise RuntimeError("PRODUCTION SAFETY ERROR: Mock database cannot be used in production. Set USE_MOCK_DB=False")
    
    # CORS Configuration
    # ENHANCED: Load from environment with secure defaults
    # PRODUCTION: Use specific allowed origins only
    cors_origins_default = [
        "http://localhost:3000",  # Frontend development server
        "http://localhost:8000",  # Backend direct access
        "http://127.0.0.1:3000",  # Alternative localhost
        "http://127.0.0.1:8000",  # Alternative localhost
        "https://zaply.in.net",    # Production domain
        "https://www.zaply.in.net", # Production domain with www
    ]
    
    # NOTE: CORS origins should be configured per environment - NEVER use wildcard "*" in production
    def _get_cors_origins(self) -> list:
        """Get CORS origins based on environment"""
        # Priority: API_BASE_URL (docker-compose compatible) > ALLOWED_ORIGINS > CORS_ORIGINS > defaults
        env_api_base_url = os.getenv("API_BASE_URL")      # From docker-compose (highest priority)
        env_allowed_origins = os.getenv("ALLOWED_ORIGINS")  # Alternative name
        env_cors_origins = os.getenv("CORS_ORIGINS")  # Legacy support (lowest priority)
        
        # FIRST: Derive CORS origins from API_BASE_URL (docker-compose compatible solution)
        if env_api_base_url:
            # Extract base domain from API_BASE_URL
            api_url = env_api_base_url.rstrip('/')
            if api_url.endswith('/api/v1'):
                # Remove /api/v1 to get base URL
                base_url = api_url[:-7]  # Remove '/api/v1'
                # Parse the URL to get the domain
                if '://' in base_url:
                    domain = base_url.split('://')[1].split(':')[0]  # Remove protocol and port
                    if domain and domain != 'localhost' and not domain.startswith('127.') and '.' in domain:
                        # Production domain derived from API_BASE_URL
                        origins = [
                            f"https://{domain}",
                            f"https://www.{domain}",
                            "http://localhost:3000",  # Development fallback
                            "http://localhost:8000",  # Development fallback
                        ]
                        print(f"[CONFIG] Derived CORS origins from API_BASE_URL: {origins}")
                        return origins
        
        # SECOND: Parse ALLOWED_ORIGINS if available
        if env_allowed_origins:
            origins = [origin.strip() for origin in env_allowed_origins.split(",") if origin.strip()]
            if origins:
                print(f"[CONFIG] Using ALLOWED_ORIGINS from environment: {origins}")
                return origins
        
        # THIRD: Parse CORS_ORIGINS if available (legacy, lowest priority)
        if env_cors_origins:
            origins = [origin.strip() for origin in env_cors_origins.split(",") if origin.strip()]
            if origins:
                print(f"[CONFIG] Using CORS_ORIGINS from environment (legacy): {origins}")
                return origins
        
        # Fallback to DEBUG/Production defaults if no environment variable
        debug_mode = os.getenv("DEBUG", "True").lower() in ("true", "1", "yes")
        
        if debug_mode:
            # Development: Allow specific localhost origins only
            print(f"[CONFIG] Using DEBUG mode CORS origins")
            return [
                "http://localhost",
                "http://localhost:8000",
                "http://localhost:3000",
                "http://127.0.0.1",
                "http://127.0.0.1:8000",
                "http://127.0.0.1:3000",
                "http://0.0.0.0:8000",
                "http://0.0.0.0:8080",
                "http://backend:8000",
                "http://frontend",
            ]
        else:
            # Production: Only allow specific domains
            print(f"[CONFIG] Using PRODUCTION mode CORS origins: {self.PRODUCTION_DOMAINS}")
            return self.PRODUCTION_DOMAINS
    
    CORS_ORIGINS: list = None  # Will be set in __init__ method
    
    # Production domain configuration
    PRODUCTION_DOMAINS: list = [
        "https://zaply.in.net",
        "https://www.zaply.in.net",
    ]
    
    def __init__(self):
        """Initialize settings and validate critical configuration"""
        self.CORS_ORIGINS = self._get_cors_origins()
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
            
            print("[EMAIL] Email service ready for use")
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
if settings.DEBUG:
    print("[CONFIG] DEBUG mode enabled - testing email service...")
    settings.validate_email_config()
