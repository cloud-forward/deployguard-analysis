"""
Main entry point for the FastAPI application.
"""
from fastapi import FastAPI
from app.api import health, analyze
from app.config import settings

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="DeployGuard Analysis Service for graph-based security risk assessment.",
    version="0.1.0"
)

# Include routers
app.include_router(health.router, tags=["General"])
app.include_router(analyze.router, prefix="/api/v1", tags=["Analysis"])

@app.get("/")
async def root():
    """Root endpoint returning basic service info."""
    return {
        "service": settings.PROJECT_NAME,
        "docs": "/docs",
        "health": "/health"
    }
