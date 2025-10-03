from pydantic_settings import BaseSettings
from pydantic import Field, validator, RedisDsn, PostgresDsn
from typing import List, Optional

class Settings(BaseSettings):
    # FastAPI
    API_PREFIX: str = "/api/v1"
    ENVIRONMENT: str = "development"  # "production" or "development"
    ENABLE_DOCS: bool = Field(True, env="ENABLE_DOCS")
    CORS_ORIGINS: str = Field("http://localhost:3000", env="CORS_ORIGINS")
    
    # Security
    SECRET_KEY: str = Field(..., env="SECRET_KEY")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 1 week
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    
    # Database
    SUPABASE_URL: str = Field(..., env="SUPABASE_URL")
    SUPABASE_KEY: str = Field(..., env="SUPABASE_KEY")
    SUPABASE_SERVICE_KEY: str = Field(..., env="SUPABASE_SERVICE_KEY")
    SUPABASE_HOST: str = Field(..., env="SUPABASE_HOST")
    SUPABASE_PORT: str = Field(..., env="SUPABASE_PORT")
    SUPABASE_DB: str = Field(..., env="SUPABASE_DB")
    SUPABASE_USER: str = Field(..., env="SUPABASE_USER")
    SUPABASE_PASSWORD: str = Field(..., env="SUPABASE_PASSWORD")
    
    # Scanners
    ZAP_BASE_URL: str = "http://localhost:8080"
    ZAP_API_KEY: str = Field(..., env="ZAP_API_KEY")
    NUCLEI_BINARY_PATH: str = "nuclei"
    WAPITI_BINARY_PATH: str = "wapiti"
    SCAN_TIMEOUT: int = 600  # 10 minutes
    
    # Redis for task queue (optional)
    REDIS_DSN: Optional[RedisDsn] = None
    
    # Notification
    SMTP_SERVER: Optional[str] = None
    SMTP_PORT: Optional[int] = None
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    NOTIFICATION_FROM: Optional[str] = None
    
    class Config:
        case_sensitive = True
        env_file = ".env"
        env_file_encoding = "utf-8"
    
    @validator("ENVIRONMENT")
    def validate_environment(cls, v):
        if v not in {"development", "production"}:
            raise ValueError("ENVIRONMENT must be 'development' or 'production'")
        return v
        
    @validator("ENABLE_DOCS", pre=True)
    def validate_enable_docs(cls, v):
        if isinstance(v, str):
            return v.lower() in {"true", "1", "yes"}
        return bool(v)

settings = Settings()