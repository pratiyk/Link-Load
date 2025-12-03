from pydantic import Field, field_validator, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List, Optional, Union

class Settings(BaseSettings):
    # FastAPI
    API_PREFIX: str = "/api/v1"
    ENVIRONMENT: str = "development"
    ENABLE_DOCS: bool = True
    CORS_ORIGINS: str = "http://localhost:3000"
    
    # Security
    SECRET_KEY: str = Field(..., description="Secret key for JWT tokens")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 1 week
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    
    # Database
    SUPABASE_URL: str = Field(..., description="Supabase project URL")
    SUPABASE_KEY: str = Field(..., description="Supabase public API key")
    SUPABASE_SERVICE_KEY: str = Field(..., description="Supabase service role API key")
    SUPABASE_HOST: str = Field(default="localhost", description="Supabase PostgreSQL host")
    SUPABASE_PORT: Union[str, int] = Field(default="54321", description="Supabase PostgreSQL port")
    SUPABASE_DB: str = Field(default="postgres", description="Supabase PostgreSQL database name")
    SUPABASE_USER: str = Field(default="postgres", description="Supabase PostgreSQL user")
    SUPABASE_PASSWORD: str = Field(default="postgres", description="Supabase PostgreSQL password")
    
    # Scanners
    ZAP_BASE_URL: str = "http://localhost:8080"
    ZAP_API_KEY: str = Field(default="zap", description="OWASP ZAP API key")
    NUCLEI_BINARY_PATH: str = "nuclei"
    NUCLEI_TEMPLATES_PATH: str = Field(default="/root/nuclei-templates", description="Nuclei templates path")
    WAPITI_BINARY_PATH: str = "wapiti"
    SCAN_TIMEOUT: int = 600  # 10 minutes
    
    # Docker Scanner Configuration (for sidecar containers)
    NUCLEI_USE_DOCKER: bool = Field(default=False, description="Use Docker container for Nuclei scans")
    NUCLEI_CONTAINER: str = Field(default="linkload-nuclei", description="Nuclei Docker container name")
    WAPITI_USE_DOCKER: bool = Field(default=False, description="Use Docker container for Wapiti scans")
    WAPITI_CONTAINER: str = Field(default="linkload-wapiti", description="Wapiti Docker container name")
    
    # Redis for task queue and caching
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: Optional[str] = None
    REDIS_DB: int = 0
    CACHE_EXPIRE_IN_SECONDS: int = 3600  # 1 hour
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = Field(default=60, description="API rate limit per minute")
    MAX_CONCURRENT_SCANS: int = Field(default=3, description="Maximum concurrent scans")
    MAX_SCANS_PER_USER_PER_DAY: int = Field(default=10, description="Maximum scans per user per day")
    MAX_SCAN_QUEUE_SIZE: int = Field(default=100, description="Maximum scan queue size")
    
    # Notification
    SMTP_SERVER: Optional[str] = None
    SMTP_PORT: Optional[int] = None
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    NOTIFICATION_FROM: Optional[str] = None
    
    # Third-party API Keys
    VT_API_KEY: Optional[str] = Field(default=None, description="VirusTotal API key")
    GSB_API_KEY: Optional[str] = Field(default=None, description="Google Safe Browsing API key")
    ABUSEIPDB_API_KEY: Optional[str] = Field(default=None, description="AbuseIPDB API key")
    SHODAN_API_KEY: Optional[str] = Field(default=None, description="Shodan API key")
    NVD_API_KEY: Optional[str] = Field(default=None, description="NVD API key")
    LEAK_LOOKUP_API_KEY: Optional[str] = Field(default=None, description="LeakLookup API key")
    RAPIDAPI_KEY: Optional[str] = Field(default=None, description="RapidAPI key")
    GOOGLE_API_KEY: Optional[str] = Field(default=None, description="Google Cloud API key")
    GOOGLE_API_CX: Optional[str] = Field(default=None, description="Google Programmable Search Engine CX (Search Engine ID)")
    WHOIS_API_KEY: Optional[str] = Field(default=None, description="WHOIS API key")
    HF_API_KEY: Optional[str] = Field(default=None, description="Hugging Face API key")
    GROQ_API_KEY: Optional[str] = Field(default=None, description="Groq API key")
    SECURITYTRAILS_API_KEY: Optional[str] = Field(default=None, description="SecurityTrails API key")
    OPENAI_API_KEY: Optional[str] = Field(default=None, description="OpenAI API key")
    
    model_config = SettingsConfigDict(
        case_sensitive=True,
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"  # Allow additional env variables
    )
    
    @field_validator("ENVIRONMENT")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        if v not in {"development", "production"}:
            raise ValueError("ENVIRONMENT must be 'development' or 'production'")
        return v
        
    @field_validator("ENABLE_DOCS", mode="before")
    @classmethod
    def validate_enable_docs(cls, v) -> bool:
        if isinstance(v, str):
            return v.lower() in {"true", "1", "yes"}
        return bool(v)
    
    @field_validator("NUCLEI_USE_DOCKER", "WAPITI_USE_DOCKER", mode="before")
    @classmethod
    def validate_docker_flags(cls, v) -> bool:
        if isinstance(v, str):
            return v.lower() in {"true", "1", "yes"}
        return bool(v)
    
    @computed_field
    @property
    def REDIS_URL(self) -> str:
        password_part = f":{self.REDIS_PASSWORD}@" if self.REDIS_PASSWORD else ""
        return f"redis://{password_part}{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

settings = Settings()