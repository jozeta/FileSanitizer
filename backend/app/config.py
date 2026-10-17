from pydantic_settings import BaseSettings
from pydantic import Field, field_validator
from typing import Optional
import os

class Settings(BaseSettings):
    APP_NAME: str = "FileSanitizer"
    APP_VERSION: str = "2.6.0"
    APP_ENV: str = "production"
    DEBUG: bool = False
    API_PREFIX: str = "/api"

    # Storage and Job Isolation
    JOBS_DIR: str = Field(default_factory=lambda: "/jobs" if os.path.exists("/jobs") and os.access("/jobs", os.W_OK) else "/tmp/filesanitizer/jobs")
    MAX_FILE_SIZE_MB: int = 100
    FILE_RETENTION_MINUTES: int = 30
    CLEANUP_INTERVAL_SECONDS: int = 300

    # Archive Analysis Limits
    MAX_ARCHIVE_FILES: int = 10000
    MAX_ARCHIVE_SIZE_MB: int = 500
    MAX_RECURSION_DEPTH: int = 5
    MAX_PROCESSING_TIME: int = 300

    # Admin Authentication
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "admin"
    ADMIN_SECRET_KEY: str = "filesanitizer-jwt-secret-key-32byte-minimum-secure-2026"

    @field_validator("ADMIN_SECRET_KEY", mode="after")
    @classmethod
    def validate_admin_secret_key(cls, v: str) -> str:
        insecure_placeholder = "filesanitizer-jwt-secret-key-32byte-minimum-secure-2026"
        app_env = os.getenv("APP_ENV", "production")
        if (not v or v == insecure_placeholder) and app_env == "production":
            secret_file = "/jobs/.jwt_secret" if os.path.exists("/jobs") else "/tmp/.filesanitizer_jwt_secret"
            try:
                if os.path.exists(secret_file):
                    with open(secret_file, "r") as f:
                        saved = f.read().strip()
                        if saved:
                            return saved
                import secrets
                new_secret = secrets.token_urlsafe(32)
                try:
                    with open(secret_file, "w") as f:
                        f.write(new_secret)
                    os.chmod(secret_file, 0o600)
                except Exception:
                    pass
                return new_secret
            except Exception:
                import secrets
                return secrets.token_urlsafe(32)
        return v or insecure_placeholder

    # YARA Rule Engine
    YARA_ENABLED: bool = True

    # ClamAV Antivirus & Definitions
    CLAMAV_ENABLED: bool = True
    CLAMAV_HOST: str = "clamav"
    CLAMAV_PORT: int = 3310
    CLAMAV_TIMEOUT: int = 30
    CLAMAV_DB_DIR: str = "/var/lib/clamav"

    # URL & IP Reputation Providers
    VIRUSTOTAL_ENABLED: bool = False
    VIRUSTOTAL_API_KEY: Optional[str] = None

    SAFE_BROWSING_ENABLED: bool = False
    SAFE_BROWSING_API_KEY: Optional[str] = None

    URLHAUS_ENABLED: bool = False
    URLHAUS_API_KEY: Optional[str] = None

    ABUSEIPDB_ENABLED: bool = False
    ABUSEIPDB_API_KEY: Optional[str] = None

    ALIENVAULT_OTX_ENABLED: bool = False
    ALIENVAULT_OTX_API_KEY: Optional[str] = None

    # Shodan Threat Intelligence API
    SHODAN_ENABLED: bool = True
    SHODAN_API_KEY: Optional[str] = None

    # Screenshot Sandbox Service
    SCREENSHOT_ENABLED: bool = True
    BROWSER_SERVICE_URL: str = "http://browser:3000/screenshot"
    SCREENSHOT_TIMEOUT: int = 15

    # Redis Broker
    REDIS_URL: Optional[str] = "redis://redis:6379/0"

    @field_validator("ADMIN_USERNAME", "ADMIN_PASSWORD", "ADMIN_SECRET_KEY", "REDIS_URL", mode="before")
    @classmethod
    def strip_whitespace_crlf(cls, v):
        if isinstance(v, str):
            return v.strip()
        return v

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"

def get_effective_jobs_dir() -> str:
    path = settings.JOBS_DIR
    if os.path.exists(path) and os.access(path, os.W_OK):
        return path
    try:
        os.makedirs(path, exist_ok=True)
        return path
    except OSError:
        fallback = "/tmp/filesanitizer/jobs"
        os.makedirs(fallback, exist_ok=True)
        return fallback

settings = Settings()
# Ensure JOBS_DIR is actually writable
settings.JOBS_DIR = get_effective_jobs_dir()

