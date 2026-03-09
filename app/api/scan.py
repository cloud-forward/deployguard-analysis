"""
Scan data ingestion endpoints.
"""
from fastapi import APIRouter, Depends
from app.models.schemas import (
    ScanStartRequest, ScanStartResponse,
    UploadUrlRequest, UploadUrlResponse,
    ScanCompleteRequest, ScanCompleteResponse,
    ScanStatusResponse,
)
from app.application.di import get_scan_service
from app.application.services.scan_service import ScanService

router = APIRouter(prefix="/api/scans", tags=["Scans"])


@router.post(
    "/start",
    response_model=ScanStartResponse,
    status_code=201,
    summary="Start a new scan session",
    description="""
Create a new scan session for a cluster. Returns a scan_id that is used 
in subsequent upload-url and complete calls.

**Scanner types:**
- `k8s` — Kubernetes cluster resources (Pods, RBAC, Secrets, Services, etc.)
- `aws` — AWS cloud resources (IAM, S3, RDS, EC2, SecurityGroups)
- `image` — Container image vulnerabilities (CVE, EPSS, signatures)
- `runtime` — Runtime security events (eBPF, CloudTrail)

Each scanner type should start its own scan session.

Only one scan per cluster and scanner_type can run at a time. If a scan is already active for the given cluster and scanner type, the API returns HTTP 409.
""",
    responses={
        201: {"description": "Scan session created successfully"},
        409: {"description": "A scan for this cluster and scanner type is already running"},
        422: {"description": "Invalid scanner_type or missing fields"},
    },
)
async def start_scan(request: ScanStartRequest, service: ScanService = Depends(get_scan_service)):
    return await service.start_scan(cluster_id=request.cluster_id, scanner_type=request.scanner_type)


@router.post(
    "/{scan_id}/upload-url",
    response_model=UploadUrlResponse,
    status_code=200,
    summary="Get presigned URL for file upload",
    description="""
Generate an S3 presigned PUT URL to upload scan result files.

The client should:
1. Call this endpoint to get the presigned URL
2. PUT the file directly to S3 using the returned URL
3. Repeat for each file if multiple files need to be uploaded
4. Call `/complete` when all files are uploaded

The presigned URL expires in 600 seconds (10 minutes).

**S3 key format:** `scans/{cluster_id}/{scan_id}/{scanner_type}/{file_name}`

The `scanner_type` is determined by the scan session (set when calling `/start`).
Each scanner writes into its own prefix. Valid scanner types are: `k8s`, `aws`, `image`.

**Examples:**
- `scans/prod-cluster/scan123/k8s/resources.json`
- `scans/prod-cluster/scan123/aws/iam.json`
- `scans/prod-cluster/scan123/image/cve.json`
""",
    responses={
        200: {"description": "Presigned URL generated"},
        404: {"description": "Scan session not found"},
        409: {"description": "Scan session already completed"},
    },
)
async def get_upload_url(scan_id: str, request: UploadUrlRequest, service: ScanService = Depends(get_scan_service)):
    return await service.get_upload_url(scan_id=scan_id, file_name=request.file_name)


@router.post(
    "/{scan_id}/complete",
    response_model=ScanCompleteResponse,
    status_code=202,
    summary="Notify scan upload completion",
    description="""
Notify the engine that all scan files have been uploaded to S3.

The engine will:
1. Verify the uploaded files exist in S3
2. Update the scan session status to "processing"
3. Trigger the analysis pipeline (graph building → attack path discovery → risk scoring)

The analysis runs asynchronously. Use `GET /api/scans/{scan_id}/status` to check progress.
""",
    responses={
        202: {"description": "Scan completion accepted, analysis triggered"},
        400: {"description": "One or more files not found in S3"},
        404: {"description": "Scan session not found"},
    },
)
async def complete_scan(scan_id: str, request: ScanCompleteRequest, service: ScanService = Depends(get_scan_service)):
    return await service.complete_scan(scan_id=scan_id, files=request.files)


@router.get(
    "/{scan_id}/status",
    response_model=ScanStatusResponse,
    status_code=200,
    summary="Get scan session status",
    description="""
Check the current status of a scan session.

**Status values:**
- `created` — Session started, no files uploaded yet
- `uploading` — At least one upload URL has been requested
- `processing` — Upload complete, analysis in progress
- `completed` — Analysis finished, results available
- `failed` — Analysis failed (check logs)
""",
    responses={
        200: {"description": "Scan session status"},
        404: {"description": "Scan session not found"},
    },
)
async def get_scan_status(scan_id: str, service: ScanService = Depends(get_scan_service)):
    return await service.get_scan_status(scan_id=scan_id)
