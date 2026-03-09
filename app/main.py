"""
Main entry point for the FastAPI application.
"""
from fastapi import FastAPI
from app.api import health, analyze, scan
from app.config import settings

app = FastAPI(
    title="DeployGuard Analysis Engine",
    description="""
DeployGuard analyzes Kubernetes and AWS infrastructure security by building 
infrastructure graphs, discovering attack paths, and recommending optimal remediations.

## Scan Data Ingestion Flow

1. **Start scan session**: `POST /api/scans/start` → receive `scan_id`
2. **Get upload URL**: `POST /api/scans/{scan_id}/upload-url` → receive S3 presigned URL
3. **Upload file**: `PUT` the file directly to the presigned URL (client → S3)
4. **Complete scan**: `POST /api/scans/{scan_id}/complete` → triggers analysis pipeline
""",
    version="4.0.0",
    openapi_tags=[
        {"name": "General"},
        {"name": "Analysis"},
        {
            "name": "Scans",
            "description": "Scan data ingestion — start scan sessions, get upload URLs, and notify completion"
        },
    ]
)

app.include_router(health.router, tags=["General"])
app.include_router(analyze.router, prefix="/api/v1", tags=["Analysis"])
app.include_router(scan.router)

@app.get("/")
async def root():
    """Root endpoint returning basic service info."""
    return {
        "service": settings.PROJECT_NAME,
        "docs": "/docs",
        "health": "/health"
    }
