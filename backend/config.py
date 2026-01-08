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
        # Use environment variable for MONGODB_URI when available (more secure)
        _MONGO_URI = os.getenv('MONGODB_URI')
        if _MONGO_URI:
            MONGODB_URI: str = _MONGO_URI
        else:
            # In production, environment variables must be set
            if not _MONGO_USER or not _MONGO_HOST or not os.getenv('MONGO_PASSWORD'):
                raise ValueError("MongoDB credentials must be set via environment variables in production")
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
    
    # CRITICAL FIX: Enhanced secret key validation with entropy requirements
    placeholder_patterns = {
        "dev-secret-key",
        "change-this-secret-key-in-production",
        "your-secret-key-change-in-production", 
        "your-secret-key",
        "test-secret-key",
        "Prod_Secret_Key_For_Zaply_Hypersend_2025_Secure_Fixed",  # Previous hardcoded value
        "hypersend_secure_password",  # Default MongoDB password
        "secret",
        "password",
        "key",
        "123456",
        "qwerty",
        "admin",
        "root",
        "test",
        "default"
    }
    
    # CRITICAL: Entropy validation for production secrets is now done inline below
    
    # CASE-INSENSITIVE placeholder detection - check if secret is exactly a placeholder
    # Store lowercase version to avoid name resolution in generator
    _secret_lower = _env_secret.lower()
    for p in placeholder_patterns:
        if _secret_lower == p.lower():
            raise ValueError(f"SECURITY ERROR: SECRET_KEY appears to be a placeholder. Set a secure, random secret key in environment variables.")
    
    # BALANCED validation: ensure minimum length with reasonable complexity
    if len(_env_secret) < 32:
        raise ValueError("SECURITY ERROR: SECRET_KEY must be at least 32 characters long")
    
    # More flexible complexity validation - accepts various secure patterns
    has_upper = any(c.isupper() for c in _env_secret)
    has_lower = any(c.islower() for c in _env_secret)
    has_digit = any(c.isdigit() for c in _env_secret)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in _env_secret)
    
    # Hex format check: accept 64+ character hex strings (256-bit keys) as secure
    # Hex strings are valid cryptographic keys even with only 2 character types
    is_hex_format = len(_env_secret) >= 64 and all(c in "0123456789abcdefABCDEF" for c in _env_secret)
    
    # Require at least 3 of 4 character types for good security (unless hex format)
    char_types = sum([has_upper, has_lower, has_digit, has_special])
    if char_types < 3 and not is_hex_format:
        raise ValueError(f"SECURITY ERROR: SECRET_KEY lacks complexity (only {char_types}/4 character types). Mix uppercase, lowercase, digits, and special characters.")
    
    SECRET_KEY: str = _env_secret
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    
    # Token expiration constants
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "28800"))  # 480 hours (20 days) for large uploads
    REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "20"))
    UPLOAD_TOKEN_EXPIRE_HOURS: int = int(os.getenv("UPLOAD_TOKEN_EXPIRE_HOURS", "480"))  # 480 hours (20 days) for very large uploads
    
    # File upload chunk settings  
    UPLOAD_CHUNK_SIZE: int = int(os.getenv("CHUNK_SIZE", "8388608"))  # 8 MiB default - Alias for backward compatibility
    
    # Upload token duration settings (in seconds)
    UPLOAD_TOKEN_DURATION: int = UPLOAD_TOKEN_EXPIRE_HOURS * 3600  # Convert hours to seconds
    UPLOAD_TOKEN_DURATION_LARGE: int = int(os.getenv("UPLOAD_TOKEN_DURATION_LARGE", "1728000"))  # 480 hours for large files (20 days)
    
    # QR Code session expiration
    QR_CODE_SESSION_EXPIRE_MINUTES: int = int(os.getenv("QR_CODE_SESSION_EXPIRE_MINUTES", "5"))
    PASSWORD_RESET_EXPIRE_MINUTES: int = int(os.getenv("PASSWORD_RESET_EXPIRE_MINUTES", "30"))
    
    # File Storage (WhatsApp-style: Local only)
    STORAGE_MODE: str = os.getenv("STORAGE_MODE", "local")  # local, server, or hybrid
    DATA_ROOT: Path = Path(os.getenv("DATA_ROOT", "./data")).resolve()  # Only for metadata/temp - normalized for cross-platform
    UPLOAD_DIR: str = os.path.normpath(os.getenv("UPLOAD_DIR", "./uploads"))  # Upload directory for chunks - cross-platform paths
    CHUNK_SIZE: int = UPLOAD_CHUNK_SIZE  # Alias to keep consistency - always use UPLOAD_CHUNK_SIZE from env
    MAX_FILE_SIZE_BYTES: int = int(os.getenv("MAX_FILE_SIZE_BYTES", "42949672960"))  # 40 GiB
    MAX_PARALLEL_CHUNKS: int = int(os.getenv("MAX_PARALLEL_CHUNKS", "4"))
    FILE_RETENTION_HOURS: int = int(os.getenv("FILE_RETENTION_HOURS", "0"))  # 0 = no server storage
    UPLOAD_EXPIRE_HOURS: int = int(os.getenv("UPLOAD_EXPIRE_HOURS", "72"))  # Extended to 72 hours (3 days) for very large files
    
    # Enhanced timeout settings for large file transfers
    CHUNK_UPLOAD_TIMEOUT_SECONDS: int = int(os.getenv("CHUNK_UPLOAD_TIMEOUT_SECONDS", "60000"))  # 10 minutes per chunk (for 40GB files)
    FILE_ASSEMBLY_TIMEOUT_MINUTES: int = int(os.getenv("FILE_ASSEMBLY_TIMEOUT_MINUTES", "300"))  # 30 minutes for assembly (40GB)
    MAX_UPLOAD_RETRY_ATTEMPTS: int = int(os.getenv("MAX_UPLOAD_RETRY_ATTEMPTS", "15"))  # More retries for large files
    
    # Large file handling optimizations
    LARGE_FILE_THRESHOLD_GB: int = int(os.getenv("LARGE_FILE_THRESHOLD_GB", "1"))  # Files > 1GB get special handling
    LARGE_FILE_CHUNK_TIMEOUT_SECONDS: int = int(os.getenv("LARGE_FILE_CHUNK_TIMEOUT_SECONDS", "900"))  # 15 minutes for large file chunks
    LARGE_FILE_THRESHOLD: int = LARGE_FILE_THRESHOLD_GB * 1024 * 1024 * 1024  # Convert GB to bytes
    
    # API
    API_HOST: str = os.getenv("API_HOST", "0.0.0.0")
    API_PORT: int = int(os.getenv("API_PORT", "8000"))  # Backend listens on 8000, Nginx proxies to it
    # Default public API base URL for this deployment
    # PROD: https://zaply.in.net/api/v1 (requires DNS + SSL setup + certbot)
    # DEV: Set API_BASE_URL=http://localhost:8080/api/v1 when port 80 unavailable
    API_BASE_URL: str = os.getenv("API_BASE_URL", "https://zaply.in.net/api/v1")
    # Server URL for QR code and other features
    SERVER_URL: str = os.getenv("SERVER_URL", API_BASE_URL.replace("/api/v1", ""))
    
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
    # SECURITY: Default DEBUG to False for production security
    # Only enable DEBUG explicitly in development environment
    debug_env = os.getenv("DEBUG", "")
    if debug_env.lower() in ("true", "1", "yes"):
        DEBUG: bool = True
    else:
        DEBUG: bool = False
    
    # Mock mode for testing without MongoDB - CRITICAL: Default to False for production
    use_mock_db_env = os.getenv("USE_MOCK_DB", "False")
    print(f"[CONFIG] USE_MOCK_DB env var: '{use_mock_db_env}'")
    USE_MOCK_DB: bool = use_mock_db_env.lower() in ("true", "1", "yes")
    print(f"[CONFIG] USE_MOCK_DB final: {USE_MOCK_DB}")
    if USE_MOCK_DB:
        print("[CONFIG] WARNING: USING MOCK DATABASE - FOR TESTING ONLY")
    
    # CRITICAL: Production safety check - allow mock DB in tests or when DEBUG is True
    # Check if we're in a test environment by looking at common test indicators
    is_test_env = 'test' in sys.modules or 'pytest' in sys.modules or os.getenv('PYTEST_CURRENT_TEST')
    if not DEBUG and not is_test_env and USE_MOCK_DB:
        raise RuntimeError("PRODUCTION SAFETY ERROR: Mock database cannot be used in production. Set USE_MOCK_DB=False")
    
    # CORS Configuration
    # ENHANCED: Load from environment with secure defaults
    # PRODUCTION: Use specific allowed origins only
    cors_origins_default = [
        "https://zaply.in.net",       # Production domain (primary)
        "https://www.zaply.in.net",   # Production domain with www
        "http://hypersend_frontend:80",  # Docker internal: frontend container
        "https://hypersend_frontend",    # Docker internal: frontend (HTTPS required)
        "https://frontend:443",           # Docker internal: frontend service (HTTPS)
        "https://frontend",              # Docker internal: frontend (HTTPS required)
        "https://hypersend_backend:8443", # Docker internal: backend for testing (HTTPS)
        # Development should use HTTPS: Configure SSL certificates locally
        # "https://localhost:3000",        # Frontend development (with HTTPS)
        # "https://localhost:8443",        # Backend direct access (with HTTPS)
    ]
    
    # NOTE: CORS origins should be configured per environment - NEVER use wildcard "*" in production
    # For subdomains, explicitly list them: https://api.zaply.in.net, https://app.zaply.in.net
    @property
    def CORS_ORIGINS(self) -> list:
        """Get CORS origins based on environment"""
        # Priority: ALLOWED_ORIGINS > CORS_ORIGINS > API_BASE_URL-derived > defaults
        env_allowed_origins = os.getenv("ALLOWED_ORIGINS")  # Highest priority: docker-compose
        env_cors_origins = os.getenv("CORS_ORIGINS")        # Alternative name
        env_api_base_url = os.getenv("API_BASE_URL")        # Used to derive domain
        
        origins = []
        
        # FIRST: Use ALLOWED_ORIGINS if explicitly provided (takes precedence)
        if env_allowed_origins:
            origins = [origin.strip() for origin in env_allowed_origins.split(",") if origin.strip()]
        
        # SECOND: Use CORS_ORIGINS if ALLOWED_ORIGINS not provided
        elif env_cors_origins:
            origins = [origin.strip() for origin in env_cors_origins.split(",") if origin.strip()]
        
        # THIRD: Derive from API_BASE_URL if neither env var is provided
        elif env_api_base_url:
            # Extract base URL from API_BASE_URL (remove /api/v1 suffix)
            base_url = env_api_base_url
            if "/api/" in base_url:
                base_url = base_url.split("/api/")[0]
            origins = [base_url]
        
        # FALLBACK: Use defaults if no environment configuration
        else:
            if self.DEBUG:
                # Development defaults
                origins = [
                    "http://localhost:3000",
                    "http://localhost:8000", 
                    "http://127.0.0.1:3000",
                    "http://127.0.0.1:8000",
                    "http://localhost:5000",
                    "http://127.0.0.1:5000"
                ]
                print(f"[CORS_SECURITY] Development mode: Mixed HTTP/HTTPS origins allowed for testing")
                print(f"[CORS_SECURITY] Total CORS origins: {len(origins)}")
                return origins
            else:
                # Production - NO WILDCARD - use secure defaults
                origins = [
                    "https://zaply.in.net",
                    "https://www.zaply.in.net",
                    "https://direct.zaply.in.net",
                    "https://www.direct.zaply.in.net"
                ]
                print(f"[CORS_SECURITY] PRODUCTION: Using secure default origins for zaply.in.net")
                print(f"[CORS_SECURITY] Configure ALLOWED_ORIGINS env var to override")
                return origins
        
        if not origins:
            # Production - NO WILDCARD - use secure defaults
            origins = [
                "https://zaply.in.net",
                "https://www.zaply.in.net", 
                "https://direct.zaply.in.net",
                "https://www.direct.zaply.in.net"
            ]
            print(f"[CORS_SECURITY] PRODUCTION: Using secure default origins for zaply.in.net")
            print(f"[CORS_SECURITY] Configure ALLOWED_ORIGINS env var to override")
            return origins
        
        # SECURITY: Filter origins based on production vs development mode
        if not self.DEBUG:
            # Production mode: ONLY allow HTTPS origins - NO EXCEPTIONS
            https_origins = [origin for origin in origins if origin.startswith("https://")]
            http_origins = [origin for origin in origins if origin.startswith("http://")]
            
            # SECURITY FIX: In production, NEVER allow HTTP origins - even Docker internal
            # All traffic must be encrypted in production environment
            if http_origins:
                print(f"[CORS_SECURITY] CRITICAL: HTTP origins detected in production - SECURITY RISK!")
                print(f"[CORS_SECURITY] CRITICAL: HTTP origins blocked: {http_origins}")
                print(f"[CORS_SECURITY] CRITICAL: Only HTTPS origins allowed in production")
                print(f"[CORS_SECURITY] CRITICAL: Configure ALLOWED_ORIGINS=https://zaply.in.net")
            
            # Only return HTTPS origins in production - NO HTTP allowed
            if https_origins:
                print(f"[CORS_SECURITY] SECURE: Production CORS origins (HTTPS only): {https_origins}")
                return https_origins
            else:
                print(f"[CORS_SECURITY] CRITICAL: No HTTPS origins configured in production!")
                print(f"[CORS_SECURITY] CRITICAL: Using secure zaply.in.net defaults")
                # SECURE FALLBACK - use zaply.in.net HTTPS defaults
                return [
                    "https://zaply.in.net",
                    "https://www.zaply.in.net", 
                    "https://direct.zaply.in.net",
                    "https://www.direct.zaply.in.net"
                ]
        else:
            # Development mode: Allow both HTTP and HTTPS for testing
            print(f"[CORS_SECURITY] Development mode: Mixed HTTP/HTTPS origins allowed for testing")
            print(f"[CORS_SECURITY] Total CORS origins: {len(origins)}")
            return origins
    
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
            # Ensure proper permissions for Linux compatibility
            old_umask = os.umask(0o022)  # Set proper umask for shared directories
            try:
                self.DATA_ROOT.mkdir(exist_ok=True, parents=True, mode=0o755)
                (self.DATA_ROOT / "tmp").mkdir(exist_ok=True, parents=True, mode=0o755)
                (self.DATA_ROOT / "files").mkdir(exist_ok=True, parents=True, mode=0o755)
                (self.DATA_ROOT / "avatars").mkdir(exist_ok=True, parents=True, mode=0o755)
                print(f"[OK] Data directories initialized at {self.DATA_ROOT}")
            finally:
                os.umask(old_umask)  # Restore original umask
        except PermissionError as e:
            print(f"[ERROR] Permission denied creating directories: {str(e)}")
            print("[ERROR] Check file permissions and user rights - this will cause runtime failures")
            raise
        except Exception as e:
            print(f"[WARN] Failed to initialize directories: {str(e)}")
            print("[WARN] Continuing with startup - check file permissions if this is critical")


settings = Settings()

# Test email service on startup in DEBUG mode
if settings.DEBUG:
    print("[CONFIG] DEBUG mode enabled - testing email service...")
    settings.validate_email_config()
