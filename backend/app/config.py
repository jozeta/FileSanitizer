from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional
import os

class Settings(BaseSettings):
    APP_NAME: str = "FileSanitizer"
    APP_ENV: str = "production"
    DEBUG: bool = False
    API_PREFIX: str = "/api"

    # Storage and Job Isolation
    JOBS_DIR: str = Field(default_factory=lambda: os.getenv("JOBS_DIR", "/jobs" if os.path.exists("/jobs") and os.access("/jobs", os.W_OK) else "/tmp/filesanitizer/jobs"))
    MAX_FILE_SIZE_MB: int = 100
    FILE_RETENTION_MINUTES: int = 30
    CLEANUP_INTERVAL_SECONDS: int = 300

    # Archive Analysis Limits
    MAX_ARCHIVE_FILES: int = 10000
    MAX_ARCHIVE_SIZE_MB: int = 500
    MAX_RECURSION_DEPTH: int = 5
    MAX_PROCESSING_TIME: int = 300

    # ClamAV Antivirus
    CLAMAV_ENABLED: bool = True
    CLAMAV_HOST: str = "clamav"
    CLAMAV_PORT: int = 3310
    CLAMAV_TIMEOUT: int = 30

    # URL Reputation Providers
    VIRUSTOTAL_ENABLED: bool = False
    VIRUSTOTAL_API_KEY: Optional[str] = None

    SAFE_BROWSING_ENABLED: bool = False
    SAFE_BROWSING_API_KEY: Optional[str] = None

    URLHAUS_ENABLED: bool = False
    URLHAUS_API_KEY: Optional[str] = None

    # Screenshot Sandbox Service
    SCREENSHOT_ENABLED: bool = True
    BROWSER_SERVICE_URL: str = "http://browser:3000/screenshot"
    SCREENSHOT_TIMEOUT: int = 15

    # Redis Broker
    REDIS_URL: Optional[str] = "redis://redis:6379/0"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"

settings = Settings()
