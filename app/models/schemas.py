"""
Pydantic schemas for request and response models.
"""
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field, field_validator
from typing import List, Optional, Dict, Any
from app.core.constants import (
    VALID_SCANNER_TYPES,
    SCAN_STATUS_CREATED,
    SCAN_STATUS_PROCESSING,
)


class AnalysisRequest(BaseModel):
    """
    Request model for the /analyze endpoint.
    """
    target_id: str = Field(..., description="ID of the target to analyze")
    depth: int = Field(default=3, ge=1, le=10)
    parameters: Optional[Dict[str, Any]] = None


class AnalysisResponse(BaseModel):
    """
    Response model for the /analyze endpoint.
    """
    job_id: str
    status: str
    message: str


class HealthResponse(BaseModel):
    """
    Response model for the /health endpoint.
    """
    status: str
    version: str



class ScanStartRequest(BaseModel):
    cluster_id: str = Field(..., description="Target cluster identifier", example="prod-cluster-01")
    scanner_type: str = Field(..., description="Type of scanner", example="k8s")

    model_config = ConfigDict(json_schema_extra={"examples": [
        {"cluster_id": "prod-cluster-01", "scanner_type": "k8s"}
    ]})

    @field_validator("scanner_type")
    @classmethod
    def validate_scanner_type(cls, v: str) -> str:
        if v not in VALID_SCANNER_TYPES:
            raise ValueError(f"scanner_type must be one of {sorted(VALID_SCANNER_TYPES)}")
        return v


class UploadUrlRequest(BaseModel):
    file_name: str = Field(..., description="Name of file to upload", example="k8s_scan_result.json")

    model_config = ConfigDict(json_schema_extra={"examples": [
        {"file_name": "k8s_scan_result.json"}
    ]})

    @field_validator("file_name")
    @classmethod
    def validate_file_name(cls, v: str) -> str:
        if not v.endswith(".json"):
            raise ValueError("file_name must end with .json")
        return v


class ScanCompleteRequest(BaseModel):
    files: list[str] = Field(
        ...,
        description="List of uploaded S3 keys",
        example=[
            "scans/prod-cluster-01/20260309T113020-k8s/k8s/scan.json",
            "scans/prod-cluster-01/20260309T113020-aws/aws/scan.json",
        ],
    )

    model_config = ConfigDict(json_schema_extra={"examples": [
        {
            "files": [
                "scans/prod-cluster-01/20260309T113020-k8s/k8s/scan.json",
                "scans/prod-cluster-01/20260309T113020-aws/aws/scan.json",
            ]
        }
    ]})

    @field_validator("files")
    @classmethod
    def validate_files_not_empty(cls, v: list) -> list:
        if not v:
            raise ValueError("files must not be empty")
        return v



class ScanStartResponse(BaseModel):
    scan_id: str = Field(..., description="Generated scan session ID", example="20260309T113020-k8s")
    status: str = Field(default=SCAN_STATUS_CREATED, description="Scan session status")

    model_config = ConfigDict(json_schema_extra={"examples": [
        {"scan_id": "20260309T113020-k8s", "status": "created"}
    ]})


class UploadUrlResponse(BaseModel):
    upload_url: str = Field(..., description="S3 presigned PUT URL")
    s3_key: str = Field(
        ...,
        description="S3 object key for the file",
        example="scans/prod-cluster-01/20260309T113020-k8s/k8s/scan.json",
    )
    expires_in: int = Field(default=600, description="URL expiration in seconds")

    model_config = ConfigDict(json_schema_extra={"examples": [
        {
            "upload_url": "https://dg-raw-scans.s3.ap-northeast-2.amazonaws.com/scans/prod-cluster-01/20260309T113020-k8s/k8s/scan.json?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=...",
            "s3_key": "scans/prod-cluster-01/20260309T113020-k8s/k8s/scan.json",
            "expires_in": 600,
        }
    ]})


class ScanCompleteResponse(BaseModel):
    scan_id: str
    status: str = Field(default=SCAN_STATUS_PROCESSING, description="Processing status")

    model_config = ConfigDict(json_schema_extra={"examples": [
        {"scan_id": "20260309T113020-k8s", "status": "processing"}
    ]})


class ScanStatusResponse(BaseModel):
    scan_id: str
    cluster_id: str
    scanner_type: str
    status: str = Field(..., description="created | uploading | processing | completed | failed")
    created_at: datetime
    completed_at: datetime | None = None
    files: list[str] = Field(default_factory=list)

    model_config = ConfigDict(json_schema_extra={"examples": [
        {
            "scan_id": "20260309T113020-k8s",
            "cluster_id": "prod-cluster-01",
            "scanner_type": "k8s",
            "status": "processing",
            "created_at": "2024-01-15T10:00:00Z",
            "completed_at": None,
            "files": [
                "scans/prod-cluster-01/20260309T113020-k8s/k8s/scan.json"
            ],
        }
    ]})
