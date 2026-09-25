from fastapi import APIRouter
from app.config import settings
from app.analyzers.clamav_scanner import ClamAVScanner

router = APIRouter(prefix="/health", tags=["Health"])

@router.get("")
def health_check():
    """System health check and component diagnostics."""
    engine, db = ClamAVScanner().get_version()
    clamav_online = (engine != "Unavailable" and engine != "Unknown")

    return {
        "status": "healthy",
        "app_name": settings.APP_NAME,
        "environment": settings.APP_ENV,
        "max_file_size_mb": settings.MAX_FILE_SIZE_MB,
        "retention_minutes": settings.FILE_RETENTION_MINUTES,
        "clamav": {
            "enabled": settings.CLAMAV_ENABLED,
            "host": settings.CLAMAV_HOST,
            "port": settings.CLAMAV_PORT,
            "reachable": clamav_online,
            "engine": engine,
            "database": db
        },
        "screenshot_service": {
            "enabled": settings.SCREENSHOT_ENABLED,
            "url": settings.BROWSER_SERVICE_URL
        },
        "reputation_services": {
            "virustotal": settings.VIRUSTOTAL_ENABLED,
            "urlhaus": settings.URLHAUS_ENABLED,
            "safebrowsing": settings.SAFE_BROWSING_ENABLED
        }
    }
