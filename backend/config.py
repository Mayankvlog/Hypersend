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
    # PROD: https://zaply.in.net/api/v1 (requires DNS + SSL setup + certbot)
    # DEV: Set API_BASE_URL=http://localhost:8080/api/v1 when port 80 unavailable
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
        "https://zaply.in.net",       # Production domain (primary)
        "https://www.zaply.in.net",   # Production domain with www
        "http://hypersend_frontend:80",  # Docker internal: frontend container
        "http://hypersend_frontend",     # Docker internal: frontend (port 80 default)
        "http://frontend:80",            # Docker internal: frontend service
        "http://frontend",               # Docker internal: frontend (port 80 default)
        "http://hypersend_backend:8000", # Docker internal: backend for testing
        "http://localhost:3000",         # Frontend development
        "http://localhost:8000",         # Backend direct access
        "http://127.0.0.1:3000",        # Alternative localhost
        "http://127.0.0.1:8000",        # Alternative localhost
    ]
    
    # NOTE: CORS origins should be configured per environment - NEVER use wildcard "*" in production
    def _get_cors_origins(self) -> list:
        """Get CORS origins based on environment"""
        # Priority: ALLOWED_ORIGINS > CORS_ORIGINS > API_BASE_URL-derived > defaults
        env_allowed_origins = os.getenv("ALLOWED_ORIGINS")  # Highest priority: docker-compose
        env_cors_origins = os.getenv("CORS_ORIGINS")        # Alternative name
        env_api_base_url = os.getenv("API_BASE_URL")        # Used to derive domain
        
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
                        if any(docker_host in origin for docker_host in ['hypersend_frontend:', 'frontend:', 'localhost:3000', '127.0.0.1:']):
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
                        print(f"[CORS_SECURITY] ℹ️  Docker internal HTTP origins (safe): {docker_http_origins}")
                    
                    if https_origins:
                        print(f"[CORS_SECURITY] ✓ Production CORS origins (HTTPS only): {https_origins}")
                    
                    # In production, allow both HTTPS and Docker internal HTTP origins
                    # Docker HTTP origins are safe (internal network only)
                    origins = https_origins + docker_http_origins
                    
                    # Validate non-empty origins after filtering
                    if not origins:
                        print(f"[CORS_SECURITY] ❌ ERROR: No valid HTTPS origins configured!")
                        print(f"[CORS_SECURITY] ❌ Please set ALLOWED_ORIGINS with HTTPS URLs in production")
                        # Fallback to default HTTPS origins to prevent complete CORS failure
                        origins = [
                            "https://zaply.in.net",
                            "https://www.zaply.in.net",
                        ]
                        print(f"[CORS_SECURITY] 🔧 Using fallback HTTPS origins: {origins}")
                
                print(f"[CONFIG] Using ALLOWED_ORIGINS from environment (highest priority): {len(origins)} origins")
                return origins
        
        # SECOND: Use CORS_ORIGINS if available (legacy, second priority)
        if env_cors_origins:
            origins = [origin.strip() for origin in env_cors_origins.split(",") if origin.strip()]
            if origins:
                print(f"[CONFIG] Using CORS_ORIGINS from environment (legacy): {len(origins)} origins")
                return origins
        
        # THIRD: Derive production domain from API_BASE_URL and add Docker hostnames
        if env_api_base_url:
            api_url = env_api_base_url.rstrip('/')
            if api_url.endswith('/api/v1'):
                base_url = api_url[:-7]  # Remove '/api/v1'
                if '://' in base_url:
                    domain = base_url.split('://')[1].split(':')[0]  # Extract domain
                    if domain and domain != 'localhost' and not domain.startswith('127.') and '.' in domain:
                        # SECURITY: Separate production HTTPS origins from dev/docker origins
                        # Production: Only HTTPS for the configured domain
                        # Docker internal: HTTP only (secure network within Docker)
                        # Development: Separate conditional logic below
                        
                        if not self.DEBUG:
                            # PRODUCTION MODE: HTTPS only, no HTTP variants
                            # This prevents man-in-the-middle attacks via unencrypted HTTP
                            origins = [
                                f"https://{domain}",          # Production HTTPS primary (https://zaply.in.net)
                                f"https://www.{domain}",      # Production HTTPS with www
                            ]
                            print(f"[CONFIG] PRODUCTION mode: {len(origins)} origins (HTTPS ONLY - secure)")
                            return origins
                        else:
                            # DEVELOPMENT MODE: Include HTTP variants and Docker internal
                            # NOTE: Docker internal communication is on private network (safe)
                            # HTTP variants only for local development setup
                            origins = [
                                # ===== PRODUCTION (HTTPS) - Primary even in dev =====
                                f"https://{domain}",          # HTTPS primary
                                f"https://www.{domain}",      # HTTPS with www
                                # ===== HTTP DEVELOPMENT FALLBACK (dev setup only) =====
                                f"http://{domain}",           # HTTP fallback for initial setup
                                f"http://www.{domain}",       # HTTP fallback with www
                                # ===== DOCKER INTERNAL (HTTP only - private network) =====
                                "http://hypersend_frontend:80",       # Docker: frontend by container name
                                "http://hypersend_frontend",          # Docker: frontend (no port)
                                "http://frontend:80",                 # Docker: frontend by service name
                                "http://frontend",                    # Docker: frontend (no port)
                                "http://hypersend_backend:8000",      # Docker: backend by container name
                                "http://backend:8000",                # Docker: backend by service name
                                # ===== LOCAL DEVELOPMENT (HTTP localhost) =====
                                "http://localhost:3000",              # Dev: frontend port
                                "http://localhost:8000",              # Dev: backend port
                                "http://localhost:8080",              # Dev: nginx fallback port
                                "http://127.0.0.1:3000",             # Dev: localhost alias frontend
                                "http://127.0.0.1:8000",             # Dev: localhost alias backend
                                "http://127.0.0.1:8080",             # Dev: localhost alias nginx
                            ]
                            print(f"[CONFIG] DEVELOPMENT mode: {len(origins)} origins (HTTPS + HTTP + Docker + Dev)")
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
        
        # SECURITY: Validate CORS configuration
        self.validate_cors_security()
        
        # Validate email configuration
        self.validate_email_config()
    
    def validate_cors_security(self):
        """Validate CORS origins for security issues"""
        # SECURITY: Check for HTTP origins in production
        if not self.DEBUG:
            http_origins = [o for o in self.CORS_ORIGINS if o.startswith('http://')]
            https_origins = [o for o in self.CORS_ORIGINS if o.startswith('https://')]
            
            if http_origins:
                # WARNING: HTTP origins are a security risk in production
                print(f"[CORS_SECURITY] ⚠️  WARNING: Production mode with HTTP origins detected!")
                print(f"[CORS_SECURITY] ⚠️  HTTP origins allow unencrypted traffic - SECURITY RISK!")
                print(f"[CORS_SECURITY] ⚠️  HTTP origins found: {http_origins}")
                print(f"[CORS_SECURITY] ⚠️  Use HTTPS only in production deployment")
            
            if https_origins:
                print(f"[CORS_SECURITY] ✓ Production CORS origins (HTTPS only): {https_origins}")
            
            if not https_origins:
                print(f"[CORS_SECURITY] ✗ ERROR: No HTTPS origins configured in production!")
                print(f"[CORS_SECURITY] ✗ Set API_BASE_URL=https://yourdomain.com/api/v1")
        else:
            # Development mode: allow mixed protocols for local testing
            print(f"[CORS_SECURITY] ℹ️  Development mode: Mixed HTTP/HTTPS origins allowed for testing")
            print(f"[CORS_SECURITY] ℹ️  Total CORS origins: {len(self.CORS_ORIGINS)}")
    
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
                print("[EMAIL] X Email service NOT configured - password reset emails will not be sent")
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
if settings.DEBUG:
    print("[CONFIG] DEBUG mode enabled - testing email service...")
    settings.validate_email_config()
