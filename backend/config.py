import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
env_path = Path(__file__).parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

# Also check current directory
if not os.getenv("MONGODB_URI"):
    load_dotenv()


class Settings:
    # MongoDB (Local server - MongoDB Compass can connect to this)
    # Priority: .env > environment variable > default
    MONGODB_URI: str = os.getenv("MONGODB_URI", "mongodb://localhost:27017/hypersend")
    
    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "CHANGE-THIS-SECRET-KEY-IN-PRODUCTION")
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
    API_BASE_URL: str = os.getenv("API_BASE_URL", "http://localhost:8000")
    
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
    # Default DEBUG to False for production safety; enable explicitly via env when needed
    DEBUG: bool = os.getenv("DEBUG", "False").lower() in ("true", "1", "yes")
    
    # CORS Configuration
    # For development: allow all origins
    # For production: restrict to specific domains (e.g., ["https://yourdomain.com", "https://app.yourdomain.com"])
    CORS_ORIGINS: list = [
        "http://localhost",
        "http://localhost:3000",
        "http://localhost:8000",
        "http://localhost:8550",
        "http://127.0.0.1",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8000",
        "http://127.0.0.1:8550",
        "http://0.0.0.0:8000",  # Docker internal
        "http://backend:8000",   # Docker service discovery
    ] if not DEBUG else ["*"]  # Allow all in development/DEBUG mode
    
    @classmethod
    def validate_production(cls):
        """Validate production-safe settings"""
        if not cls.DEBUG:
            # Production mode validations
            if cls.SECRET_KEY == "CHANGE-THIS-SECRET-KEY-IN-PRODUCTION":
                raise ValueError(
                    "CRITICAL: SECRET_KEY must be changed in production! "
                    "Generate with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
                )
            if cls.CORS_ORIGINS == ["*"]:
                raise ValueError(
                    "CRITICAL: CORS_ORIGINS set to wildcard in production! "
                    "Update config.py CORS_ORIGINS to specific domains only."
                )
            print("[INFO] Production validations passed")
        else:
            print("[INFO] Debug mode enabled - production validations skipped")
    
    @classmethod
    def init_directories(cls):
        """Create necessary directories"""
        cls.DATA_ROOT.mkdir(exist_ok=True)
        (cls.DATA_ROOT / "tmp").mkdir(exist_ok=True)
        (cls.DATA_ROOT / "files").mkdir(exist_ok=True)


settings = Settings()
settings.init_directories()
