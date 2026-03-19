"""
요청 및 응답 모델을 위한 Pydantic 스키마.
"""
from datetime import datetime
from enum import Enum
from typing import Literal
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from typing import List, Optional, Dict, Any
from app.core.constants import (
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_QUEUED,
)


class ScannerType(str, Enum):
    k8s = "k8s"
    aws = "aws"
    image = "image"
    runtime = "runtime"


RequestSource = Literal["manual", "scheduled"]


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
    request_source: RequestSource = Field(
        default="manual",
        description="Source of the scan request",
        example="manual",
    )

    model_config = ConfigDict(json_schema_extra={"examples": [
        {
            "cluster_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "scanner_type": "k8s",
            "request_source": "manual",
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
    status: str = Field(default=SCAN_STATUS_COMPLETED, description="스캔 완료 상태")

    model_config = ConfigDict(json_schema_extra={"examples": [
        {"scan_id": "20260309T113020-k8s", "status": "completed"}
    ]})


class ScanStatusResponse(BaseModel):
    scan_id: str
    cluster_id: str
    scanner_type: str
    status: str = Field(..., description="queued | running | uploading | completed | failed")
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


ALLOWED_CLUSTER_TYPES = ("eks", "self-managed", "aws")


class ClusterCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255, description="클러스터 고유 이름", example="prod-cluster-01")
    description: Optional[str] = Field(None, max_length=1000, description="클러스터 설명", example="프로덕션 EKS 클러스터")
    cluster_type: Optional[str] = Field(None, description="클러스터 유형: 'eks' | 'self-managed' | 'aws'", example="eks")
    aws_account_id: Optional[str] = Field(None, description="Discovery Inventory용 AWS account id", example="123456789012")
    aws_role_arn: Optional[str] = Field(None, description="Discovery sync용 AssumeRole ARN")
    aws_region: Optional[str] = Field(None, description="Discovery Inventory 기본 AWS 리전", example="ap-northeast-2")

    model_config = ConfigDict(json_schema_extra={"examples": [
        {"name": "prod-cluster-01", "description": "프로덕션 EKS 클러스터", "cluster_type": "eks"}
    ]})

    @model_validator(mode="after")
    def default_inventory_cluster_type(self) -> "ClusterCreateRequest":
        has_inventory_fields = any(
            value is not None
            for value in (self.aws_account_id, self.aws_role_arn, self.aws_region)
        )
        if self.cluster_type is None and has_inventory_fields:
            self.cluster_type = "aws"
        if self.cluster_type is None:
            raise ValueError("cluster_type is required unless AWS discovery fields are provided")
        return self

    @field_validator("cluster_type")
    @classmethod
    def validate_cluster_type(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        if v not in ALLOWED_CLUSTER_TYPES:
            raise ValueError("cluster_type must be one of 'eks', 'self-managed', or 'aws'")
        return v


class ClusterUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255, description="변경할 클러스터 이름", example="prod-cluster-02")
    description: Optional[str] = Field(None, max_length=1000, description="변경할 클러스터 설명", example="업데이트된 설명")
    cluster_type: Optional[str] = Field(None, description="변경할 클러스터 유형: 'eks' | 'self-managed' | 'aws'", example="self-managed")

    model_config = ConfigDict(json_schema_extra={"examples": [
        {"name": "prod-cluster-02", "cluster_type": "self-managed"}
    ]})

    @field_validator("cluster_type")
    @classmethod
    def validate_cluster_type(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in ALLOWED_CLUSTER_TYPES:
            raise ValueError("cluster_type must be one of 'eks', 'self-managed', or 'aws'")
        return v


class ClusterResponse(BaseModel):
    id: str = Field(..., description="클러스터 고유 ID", example="a1b2c3d4-e5f6-7890-abcd-ef1234567890")
    name: str = Field(..., description="클러스터 이름", example="prod-cluster-01")
    description: Optional[str] = Field(None, description="클러스터 설명", example="프로덕션 EKS 클러스터")
    cluster_type: Optional[str] = Field(None, description="클러스터 유형", example="eks")
    aws_account_id: Optional[str] = Field(None, description="AWS account id", example="123456789012")
    aws_role_arn: Optional[str] = Field(None, description="Discovery sync용 AssumeRole ARN")
    aws_region: Optional[str] = Field(None, description="AWS region", example="ap-northeast-2")
    created_at: Optional[datetime] = Field(None, description="생성 일시")
    updated_at: Optional[datetime] = Field(None, description="최종 수정 일시")

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={"examples": [{
            "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "name": "prod-cluster-01",
            "description": "프로덕션 EKS 클러스터",
            "cluster_type": "eks",
            "aws_account_id": "123456789012",
            "aws_role_arn": "arn:aws:iam::123456789012:role/deployguard-discovery",
            "aws_region": "ap-northeast-2",
            "created_at": "2024-01-15T10:00:00Z",
            "updated_at": "2024-01-15T10:00:00Z",
        }]}
    )


class ClusterOnboardingResponse(BaseModel):
    installation_method: str = Field(..., description="설치 방식", example="helm")
    install_command: str = Field(..., description="설치 명령", example="helm upgrade --install deployguard-scanner deployguard/scanner")
    required_values: dict[str, str] = Field(default_factory=dict, description="설치에 필요한 값")
    required_environment_variables: list[str] = Field(default_factory=list, description="필수 환경 변수 이름 목록")
    guidance: list[str] = Field(default_factory=list, description="추가 설치 가이드")


class ClusterCreateResponse(BaseModel):
    id: str = Field(..., description="클러스터 고유 ID", example="a1b2c3d4-e5f6-7890-abcd-ef1234567890")
    name: str = Field(..., description="클러스터 이름", example="prod-cluster-01")
    description: Optional[str] = Field(None, description="클러스터 설명", example="프로덕션 EKS 클러스터")
    cluster_type: str = Field(..., description="클러스터 유형", example="eks")
    aws_account_id: Optional[str] = Field(None, description="AWS account id", example="123456789012")
    aws_role_arn: Optional[str] = Field(None, description="Discovery sync용 AssumeRole ARN")
    aws_region: Optional[str] = Field(None, description="AWS region", example="ap-northeast-2")
    api_token: str = Field(..., description="스캐너 인증용 API 토큰", example="dg_scanner_xxxxxxxxxxxxxxxxxxxxx")
    onboarding: ClusterOnboardingResponse = Field(..., description="클러스터 유형별 설치 가이드")
    created_at: datetime = Field(..., description="생성 일시")
    updated_at: datetime = Field(..., description="최종 수정 일시")

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={"examples": [{
            "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "name": "prod-cluster-01",
            "description": "프로덕션 EKS 클러스터",
            "cluster_type": "eks",
            "aws_account_id": "123456789012",
            "aws_role_arn": "arn:aws:iam::123456789012:role/deployguard-discovery",
            "aws_region": "ap-northeast-2",
            "api_token": "dg_scanner_xxxxxxxxxxxxxxxxxxxxx",
            "onboarding": {
                "installation_method": "helm",
                "install_command": "helm upgrade --install deployguard-scanner deployguard/scanner",
                "required_values": {
                    "clusterId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                    "apiToken": "dg_scanner_xxxxxxxxxxxxxxxxxxxxx",
                    "imagePullSecret": "deployguard-registry"
                },
                "required_environment_variables": [],
                "guidance": [
                    "Set clusterId and apiToken in the Helm values.",
                    "Configure imagePullSecret so the scanner image can be pulled."
                ]
            },
            "created_at": "2024-01-15T10:00:00Z",
            "updated_at": "2024-01-15T10:00:00Z",
        }]}
    )


class ClusterListResponse(BaseModel):
    clusters: list[ClusterResponse] = Field(default_factory=list)


class SyncResponse(BaseModel):
    status: str
    cluster_id: str
    scan_id: str


class AssetStatusResponse(BaseModel):
    discovered: bool = True
    source: str = "aws"


class InventorySummaryResponse(BaseModel):
    total_assets: int = 0


class AssetInventoryItemResponse(BaseModel):
    asset_id: str
    asset_type: str
    name: str
    cluster_id: str
    cluster_name: str
    account_id: str
    region: str | None = None
    status: AssetStatusResponse
    details: dict[str, Any] = Field(default_factory=dict)


class AssetInventoryListResponse(BaseModel):
    summary: InventorySummaryResponse
    assets: list[AssetInventoryItemResponse] = Field(default_factory=list)


class AssetDetailResponse(AssetInventoryItemResponse):
    pass
