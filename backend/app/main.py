from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.core.logging_config import logger
from app.core.retention import retention_cleaner
from app.api.files import router as files_router
from app.api.jobs import router as jobs_router
from app.api.health import router as health_router
from app.api.settings import router as settings_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Start retention cleanup daemon
    retention_cleaner.start()
    logger.info(f"FileSanitizer backend started. Environment: {settings.APP_ENV}")
    yield
    # Shutdown: Stop retention cleanup daemon
    retention_cleaner.stop()
    logger.info("FileSanitizer backend shutting down.")

import os

is_prod = settings.APP_ENV == "production" and not settings.DEBUG

app = FastAPI(
    title=settings.APP_NAME,
    description="File sanitization, malware analysis, metadata removal, and Content Disarm & Reconstruction (CDR) platform.",
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url=None if is_prod else "/docs",
    redoc_url=None if is_prod else "/redoc",
    openapi_url=None if is_prod else "/openapi.json"
)

# Explicit CORS Origins Allowlist (mitigates FS-SEC-004 reflective wildcard CORS)
ALLOWED_CORS_ORIGINS = [
    "http://localhost",
    "http://localhost:80",
    "http://localhost:8080",
    "http://localhost:3000",
    "http://127.0.0.1",
    "http://127.0.0.1:80",
    "http://127.0.0.1:8080",
    "http://127.0.0.1:3000",
]
env_cors = os.getenv("CORS_ORIGINS")
if env_cors:
    ALLOWED_CORS_ORIGINS.extend([o.strip() for o in env_cors.split(",") if o.strip()])

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(files_router, prefix=settings.API_PREFIX)
app.include_router(jobs_router, prefix=settings.API_PREFIX)
app.include_router(health_router, prefix=settings.API_PREFIX)
app.include_router(settings_router, prefix=settings.API_PREFIX)

@app.get("/")
def root():
    return {
        "app": settings.APP_NAME,
        "motto": "Don't trust the file. Wash it first.",
        "status": "online",
        "api_docs": "/docs"
    }
