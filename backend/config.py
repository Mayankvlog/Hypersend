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
    # MongoDB runs in Docker container as part of docker-compose
    # Backend connects to MongoDB via Docker service name "mongodb" on internal network
    # Data persisted on VPS at /var/lib/mongodb
    
    # Read MongoDB credentials from environment
    _MONGO_USER: str = os.getenv("MONGO_USER", "hypersend")
    _MONGO_PASSWORD: str = os.getenv("MONGO_PASSWORD", "hypersend_secure_password")
    _MONGO_HOST: str = os.getenv("MONGO_HOST", "mongodb")
    _MONGO_PORT: str = os.getenv("MONGO_PORT", "27017")
    _MONGO_DB: str = os.getenv("MONGO_INITDB_DATABASE", "hypersend")
    
    # Construct MONGODB_URI with proper URL encoding for special characters in password
    # quote_plus handles special chars like @#$% → %40%23%24%25
    MONGODB_URI: str = f"mongodb://{quote_plus(_MONGO_USER)}:{quote_plus(_MONGO_PASSWORD)}@{_MONGO_HOST}:{_MONGO_PORT}/{_MONGO_DB}?authSource=admin&retryWrites=true"
    
    # Security
    # Use a constant fallback if env is missing to prevent session invalidation on restart
    _env_secret = os.getenv("SECRET_KEY")
    SECRET_KEY: str = _env_secret if _env_secret else "fallback-insecure-dev-key-do-not-use-in-prod-hypersend"
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
    REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "30"))
    
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
    API_PORT: int = int(os.getenv("API_PORT", "8000"))
    # Default public API base URL for this deployment (VPS behind Nginx HTTPS)
    # Note: Nginx proxies /api/ to backend, so full URL includes /api/v1
    API_BASE_URL: str = os.getenv("API_BASE_URL", "https://zaply.in.net/api/v1/")
    
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
    
    # Development
    # Default DEBUG to True for development; set to False in production with proper SECRET_KEY
    DEBUG: bool = os.getenv("DEBUG", "True").lower() in ("true", "1", "yes")
    
    # CORS Configuration
    # Restrict CORS even without domain for better security
    CORS_ORIGINS: list = os.getenv("CORS_ORIGINS", "").split(",") if os.getenv("CORS_ORIGINS") else [
        "http://localhost",
        "http://localhost:8000",
        "http://localhost:8550",
        "http://localhost:64216",
        "http://127.0.0.1:8000",
        "http://127.0.0.1:8550",
        "http://127.0.0.1:64216",
        "http://0.0.0.0:8000",
        "http://backend:8000",
        # Add VPS IP / domain (HTTP + HTTPS) and production frontend
        "http://139.59.82.105",
        "http://139.59.82.105:8000",
        "http://139.59.82.105:8550",
        "https://139.59.82.105",
        "http://zaply.in.net",
        "https://zaply.in.net",
        "https://www.zaply.in.net",
    ]
    
    def __init__(self):
        """Initialize settings and validate critical configuration"""
        self.validate_config()
    
    def validate_config(self):
        """Validate critical configuration"""
        # Generate secure SECRET_KEY if not set
        if not self.SECRET_KEY or self.SECRET_KEY in ["dev-secret-key-change-in-production-5y7L9x2K", "your-super-secret-production-key-change-this-2025"]:
            self.SECRET_KEY = secrets.token_urlsafe(64)
            if not os.getenv("SECRET_KEY"):
                print("[WARN] SECRET_KEY not set in environment. For persistent tokens across restarts, set SECRET_KEY in .env")
        
        if len(self.SECRET_KEY) < 32:
            self.SECRET_KEY = secrets.token_urlsafe(64)
    
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
            print(f"[OK] Data directories initialized at {self.DATA_ROOT}")
        except Exception as e:
            print(f"[WARN] Failed to initialize directories: {str(e)}")
            print("[WARN] Continuing with startup - check file permissions if this is critical")


settings = Settings()
