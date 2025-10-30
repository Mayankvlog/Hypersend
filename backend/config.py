import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()


class Settings:
    # MongoDB
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
    
    # API
    API_HOST: str = os.getenv("API_HOST", "0.0.0.0")
    API_PORT: int = int(os.getenv("API_PORT", "8000"))
    API_BASE_URL: str = os.getenv("API_BASE_URL", "http://localhost:8000")
    
    # Rate Limiting
    RATE_LIMIT_PER_USER: int = int(os.getenv("RATE_LIMIT_PER_USER", "100"))
    RATE_LIMIT_WINDOW_SECONDS: int = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
    
    # Development
    DEBUG: bool = os.getenv("DEBUG", "True").lower() in ("true", "1", "yes")
    
    @classmethod
    def init_directories(cls):
        """Create necessary directories"""
        cls.DATA_ROOT.mkdir(exist_ok=True)
        (cls.DATA_ROOT / "tmp").mkdir(exist_ok=True)
        (cls.DATA_ROOT / "files").mkdir(exist_ok=True)


settings = Settings()
settings.init_directories()
