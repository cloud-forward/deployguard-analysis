"""
요청 및 응답 모델을 위한 Pydantic 스키마.
"""
from datetime import datetime
from enum import Enum
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field, field_validator
from typing import List, Optional, Dict, Any
from app.core.constants import (
    SCAN_STATUS_QUEUED,
    SCAN_STATUS_PROCESSING,
)


class ScannerType(str, Enum):
    k8s = "k8s"
    aws = "aws"
    image = "image"
    runtime = "runtime"


class AnalysisJobRequest(BaseModel):
    cluster_id: str = Field(..., description="분석 대상 클러스터 ID", example="prod-cluster-01")
    k8s_scan_id: str = Field(..., description="Kubernetes 스캔 세션 ID", example="20260309T113020-k8s")
    aws_scan_id: str = Field(..., description="AWS 스캔 세션 ID", example="20260309T113020-aws")
    image_scan_id: str = Field(..., description="컨테이너 이미지 스캔 세션 ID", example="20260309T113020-image")

    model_config = ConfigDict(json_schema_extra={"examples": [
        {
            "cluster_id": "prod-cluster-01",
            "k8s_scan_id": "20260309T113020-k8s",
            "aws_scan_id": "20260309T113020-aws",
            "image_scan_id": "20260309T113020-image",
        }
    ]})


class AnalysisJobResponse(BaseModel):
    job_id: str = Field(..., description="생성된 분석 작업 ID", example="job-20260313-001")
    status: str = Field(..., description="작업 상태", example="accepted")
    message: str = Field(..., description="상태 메시지", example="분석 작업이 시작되었습니다")

    model_config = ConfigDict(json_schema_extra={"examples": [
        {"job_id": "job-20260313-001", "status": "accepted", "message": "분석 작업이 시작되었습니다"}
    ]})


class HealthResponse(BaseModel):
    """
    /health 엔드포인트의 응답 모델.
    """
    status: str
    version: str



class ScanStartRequest(BaseModel):
    cluster_id: UUID = Field(
        ...,
        description="UUID of the Kubernetes cluster registered in DeployGuard",
        example="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    )
    scanner_type: ScannerType = Field(
        ...,
        description="Type of scanner to run. One of: k8s, aws, image",
        example="k8s",
    )
    request_source: str = Field(
        default="api",
        description="Source of the scan request (e.g. scanner-orchestrator, manual-api)",
        example="scanner-orchestrator",
    )

    model_config = ConfigDict(json_schema_extra={"examples": [
        {
            "cluster_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "scanner_type": "k8s",
            "request_source": "scanner-orchestrator",
        }
    ]})


class UploadUrlRequest(BaseModel):
    file_name: str = Field(..., description="업로드할 파일 이름", example="k8s_scan_result.json")

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
        description="업로드된 S3 키 목록",
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
    scan_id: str = Field(..., description="생성된 스캔 세션 ID", example="20260309T113020-k8s")
    status: str = Field(default=SCAN_STATUS_QUEUED, description="스캔 세션 상태")

    model_config = ConfigDict(json_schema_extra={"examples": [
        {"scan_id": "20260309T113020-k8s", "status": "queued"}
    ]})


class UploadUrlResponse(BaseModel):
    upload_url: str = Field(..., description="S3 presigned PUT URL")
    s3_key: str = Field(
        ...,
        description="파일의 S3 오브젝트 키",
        example="scans/prod-cluster-01/20260309T113020-k8s/k8s/scan.json",
    )
    expires_in: int = Field(default=600, description="URL 만료 시간(초)")

    model_config = ConfigDict(json_schema_extra={"examples": [
        {
            "upload_url": "https://dg-raw-scans.s3.ap-northeast-2.amazonaws.com/scans/prod-cluster-01/20260309T113020-k8s/k8s/scan.json?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=...",
            "s3_key": "scans/prod-cluster-01/20260309T113020-k8s/k8s/scan.json",
            "expires_in": 600,
        }
    ]})


class ScanCompleteResponse(BaseModel):
    scan_id: str
    status: str = Field(default=SCAN_STATUS_PROCESSING, description="처리 상태")

    model_config = ConfigDict(json_schema_extra={"examples": [
        {"scan_id": "20260309T113020-k8s", "status": "processing"}
    ]})


class ScanStatusResponse(BaseModel):
    scan_id: str
    cluster_id: str
    scanner_type: str
    status: str = Field(..., description="queued | running | uploading | processing | completed | failed")
    created_at: datetime
    completed_at: datetime | None = None
    files: list[str] = Field(default_factory=list)

    model_config = ConfigDict(json_schema_extra={"examples": [
        {
            "scan_id": "20260309T113020-k8s",
            "cluster_id": "prod-cluster-01",
            "scanner_type": "k8s",
            "status": "queued",
            "created_at": "2024-01-15T10:00:00Z",
            "completed_at": None,
            "files": [
                "scans/prod-cluster-01/20260309T113020-k8s/k8s/scan.json"
            ],
        }
    ]})


class PendingScanClaimResponse(BaseModel):
    scan_id: str
    cluster_id: str
    scanner_type: str
    status: str = Field(..., description="running")
    claimed_by: str
    claimed_at: datetime
    started_at: datetime
    lease_expires_at: datetime
    files: list[str] = Field(default_factory=list)


class ClusterCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255, description="클러스터 고유 이름", example="prod-cluster-01")
    description: Optional[str] = Field(None, max_length=1000, description="클러스터 설명", example="프로덕션 EKS 클러스터")
    cluster_type: str = Field(..., description="클러스터 유형: 'eks' | 'self-managed'", example="eks")

    model_config = ConfigDict(json_schema_extra={"examples": [
        {"name": "prod-cluster-01", "description": "프로덕션 EKS 클러스터", "cluster_type": "eks"}
    ]})

    @field_validator("cluster_type")
    @classmethod
    def validate_cluster_type(cls, v: str) -> str:
        if v not in ("eks", "self-managed"):
            raise ValueError("cluster_type must be either 'eks' or 'self-managed'")
        return v


class ClusterUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255, description="변경할 클러스터 이름", example="prod-cluster-02")
    description: Optional[str] = Field(None, max_length=1000, description="변경할 클러스터 설명", example="업데이트된 설명")
    cluster_type: Optional[str] = Field(None, description="변경할 클러스터 유형: 'eks' | 'self-managed'", example="self-managed")

    model_config = ConfigDict(json_schema_extra={"examples": [
        {"name": "prod-cluster-02", "cluster_type": "self-managed"}
    ]})

    @field_validator("cluster_type")
    @classmethod
    def validate_cluster_type(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in ("eks", "self-managed"):
            raise ValueError("cluster_type must be either 'eks' or 'self-managed'")
        return v


class ClusterResponse(BaseModel):
    id: str = Field(..., description="클러스터 고유 ID", example="a1b2c3d4-e5f6-7890-abcd-ef1234567890")
    name: str = Field(..., description="클러스터 이름", example="prod-cluster-01")
    description: Optional[str] = Field(None, description="클러스터 설명", example="프로덕션 EKS 클러스터")
    cluster_type: str = Field(..., description="클러스터 유형", example="eks")
    created_at: datetime = Field(..., description="생성 일시")
    updated_at: datetime = Field(..., description="최종 수정 일시")

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={"examples": [{
            "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "name": "prod-cluster-01",
            "description": "프로덕션 EKS 클러스터",
            "cluster_type": "eks",
            "created_at": "2024-01-15T10:00:00Z",
            "updated_at": "2024-01-15T10:00:00Z",
        }]}
    )


class ClusterCreateResponse(BaseModel):
    id: str = Field(..., description="클러스터 고유 ID", example="a1b2c3d4-e5f6-7890-abcd-ef1234567890")
    name: str = Field(..., description="클러스터 이름", example="prod-cluster-01")
    description: Optional[str] = Field(None, description="클러스터 설명", example="프로덕션 EKS 클러스터")
    cluster_type: str = Field(..., description="클러스터 유형", example="eks")
    api_token: str = Field(..., description="스캐너 인증용 API 토큰", example="dg_scanner_xxxxxxxxxxxxxxxxxxxxx")
    created_at: datetime = Field(..., description="생성 일시")
    updated_at: datetime = Field(..., description="최종 수정 일시")

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={"examples": [{
            "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "name": "prod-cluster-01",
            "description": "프로덕션 EKS 클러스터",
            "cluster_type": "eks",
            "api_token": "dg_scanner_xxxxxxxxxxxxxxxxxxxxx",
            "created_at": "2024-01-15T10:00:00Z",
            "updated_at": "2024-01-15T10:00:00Z",
        }]}
    )
