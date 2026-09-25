from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.core.logging_config import logger
from app.core.retention import retention_cleaner
from app.api.files import router as files_router
from app.api.jobs import router as jobs_router
from app.api.health import router as health_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Start retention cleanup daemon
    retention_cleaner.start()
    logger.info(f"FileSanitizer backend started. Environment: {settings.APP_ENV}")
    yield
    # Shutdown: Stop retention cleanup daemon
    retention_cleaner.stop()
    logger.info("FileSanitizer backend shutting down.")

app = FastAPI(
    title=settings.APP_NAME,
    description="File sanitization, malware analysis, metadata removal, and Content Disarm & Reconstruction (CDR) platform.",
    version="1.0.0",
    lifespan=lifespan
)

# CORS Middleware (permits local dev and frontend container requests)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(files_router, prefix=settings.API_PREFIX)
app.include_router(jobs_router, prefix=settings.API_PREFIX)
app.include_router(health_router, prefix=settings.API_PREFIX)

@app.get("/")
def root():
    return {
        "app": settings.APP_NAME,
        "motto": "Don't trust the file. Wash it first.",
        "status": "online",
        "api_docs": "/docs"
    }
