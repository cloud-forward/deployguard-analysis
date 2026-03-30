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
    SCAN_STATUS_CREATED,
    SCAN_STATUS_FAILED,
    SCAN_STATUS_PROCESSING,
)


class ScannerType(str, Enum):
    k8s = "k8s"
    aws = "aws"
    image = "image"


RequestSource = Literal["manual", "scheduled"]


class AnalysisJobRequest(BaseModel):
    k8s_scan_id: str | None = Field(None, description="Kubernetes 스캔 세션 ID", example="20260309T113020-k8s")
    aws_scan_id: str | None = Field(None, description="AWS 스캔 세션 ID", example="20260309T113020-aws")
    image_scan_id: str | None = Field(None, description="컨테이너 이미지 스캔 세션 ID", example="20260309T113020-image")

    model_config = ConfigDict(json_schema_extra={"examples": [
        {
            "k8s_scan_id": "20260309T113020-k8s",
            "aws_scan_id": "20260309T113020-aws",
            "image_scan_id": "20260309T113020-image",
        }
    ]})

    @model_validator(mode="after")
    def validate_at_least_one_scan(self) -> "AnalysisJobRequest":
        if not any((self.k8s_scan_id, self.aws_scan_id, self.image_scan_id)):
            raise ValueError("At least one scan ID must be provided")
        return self


class DebugAnalysisExecuteRequest(BaseModel):
    k8s_scan_id: str | None = Field(None, description="Kubernetes 스캔 세션 ID", example="20260309T113020-k8s")
    aws_scan_id: str | None = Field(None, description="AWS 스캔 세션 ID", example="20260309T113020-aws")
    image_scan_id: str | None = Field(None, description="컨테이너 이미지 스캔 세션 ID", example="20260309T113020-image")

    model_config = ConfigDict(json_schema_extra={"examples": [
        {
            "k8s_scan_id": "20260309T113020-k8s",
            "aws_scan_id": "20260309T113020-aws",
            "image_scan_id": "20260309T113020-image",
        },
        {
            "k8s_scan_id": "20260309T113020-k8s",
            "image_scan_id": "20260309T113020-image",
        },
        {
            "aws_scan_id": "20260309T113020-aws",
        },
    ]})

    @model_validator(mode="after")
    def validate_at_least_one_scan(self) -> "DebugAnalysisExecuteRequest":
        if not any((self.k8s_scan_id, self.aws_scan_id, self.image_scan_id)):
            raise ValueError("At least one scan ID must be provided")
        return self


class AnalysisJobResponse(BaseModel):
    job_id: str = Field(..., description="생성된 분석 작업 ID", example="job-20260313-001")
    status: str = Field(..., description="작업 상태", example="accepted")
    message: str = Field(..., description="상태 메시지", example="분석 작업이 시작되었습니다")

    model_config = ConfigDict(json_schema_extra={"examples": [
        {"job_id": "job-20260313-001", "status": "accepted", "message": "분석 작업이 시작되었습니다"}
    ]})


class AnalysisJobSummaryResponse(BaseModel):
    job_id: str
    status: str
    current_step: str | None = None
    k8s_scan_id: str | None = None
    aws_scan_id: str | None = None
    image_scan_id: str | None = None
    expected_scans: list[str] = Field(default_factory=list)
    error_message: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    graph_id: str | None = None

    model_config = ConfigDict(json_schema_extra={"examples": [
        {
            "job_id": "job-20260313-001",
            "status": "running",
            "current_step": "graph_building",
            "k8s_scan_id": "20260309T113020-k8s",
            "aws_scan_id": None,
            "image_scan_id": "20260309T113020-image",
            "expected_scans": ["k8s", "image"],
            "error_message": None,
            "created_at": "2024-01-15T10:00:00Z",
            "started_at": "2024-01-15T10:00:05Z",
            "completed_at": None,
            "graph_id": None,
        }
    ]})


class AnalysisJobDetailResponse(AnalysisJobSummaryResponse):
    cluster_id: str

    model_config = ConfigDict(json_schema_extra={"examples": [
        {
            "job_id": "job-20260313-001",
            "cluster_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "status": "completed",
            "current_step": None,
            "k8s_scan_id": "20260309T113020-k8s",
            "aws_scan_id": "20260309T113020-aws",
            "image_scan_id": "20260309T113020-image",
            "expected_scans": ["k8s", "aws", "image"],
            "error_message": None,
            "created_at": "2024-01-15T10:00:00Z",
            "started_at": "2024-01-15T10:00:05Z",
            "completed_at": "2024-01-15T10:00:45Z",
            "graph_id": "graph-20260313-001",
        }
    ]})


class AnalysisResultSummaryResponse(BaseModel):
    graph_id: str | None = None
    generated_at: datetime | None = None
    graph_status: str | None = None
    node_count: int = 0
    edge_count: int = 0
    entry_point_count: int = 0
    crown_jewel_count: int = 0
    attack_path_count: int = 0
    remediation_recommendation_count: int = 0


class AnalysisResultLinksResponse(BaseModel):
    analysis_job: str
    attack_graph: str | None = None
    attack_paths: str | None = None
    remediation_recommendations: str | None = None
    link_scope: str = "cluster_latest_view"


class ClusterAnalysisJobListResponse(BaseModel):
    items: list[AnalysisJobSummaryResponse] = Field(default_factory=list)
    total: int

    model_config = ConfigDict(json_schema_extra={"examples": [
        {
            "items": [
                {
                    "job_id": "job-20260313-001",
                    "status": "pending",
                    "current_step": None,
                    "k8s_scan_id": "20260309T113020-k8s",
                    "aws_scan_id": None,
                    "image_scan_id": "20260309T113020-image",
                    "expected_scans": ["k8s", "image"],
                    "error_message": None,
                    "created_at": "2024-01-15T10:00:00Z",
                    "started_at": None,
                    "completed_at": None,
                    "graph_id": None,
                }
            ],
            "total": 1,
        }
    ]})


class HealthResponse(BaseModel):
    """
    /health 엔드포인트의 응답 모델.
    """
    status: str
    version: str


class UserSummaryResponse(BaseModel):
    id: str
    email: str
    name: str | None = None
    is_active: bool


class UserOverviewResponse(BaseModel):
    total_assets: int = 0
    k8s_assets: int = 0
    aws_assets: int = 0
    public_assets: int = 0
    entry_point_assets: int = 0
    crown_jewel_assets: int = 0


class UserAssetListItemResponse(BaseModel):
    cluster_id: str
    name: str
    cluster_type: str
    aws_account_id: str | None = None
    aws_region: str | None = None
    analysis_job_count: int = 0
    scan_record_count: int = 0
    latest_analysis_status: str | None = None
    latest_scan_status: str | None = None


class UserAssetListResponse(BaseModel):
    items: list[UserAssetListItemResponse] = Field(default_factory=list)
    total: int = 0


class MeAssetInventoryItemResponse(BaseModel):
    asset_id: str
    asset_type: str
    asset_domain: str | None = None
    name: str
    cluster_id: str | None = None
    cluster_name: str | None = None
    aws_account_id: str | None = None
    aws_region: str | None = None
    base_risk: float | None = None
    is_public: bool | None = None
    is_entry_point: bool | None = None
    is_crown_jewel: bool | None = None


class MeAssetInventoryListResponse(BaseModel):
    items: list[MeAssetInventoryItemResponse] = Field(default_factory=list)
    total: int = 0


class UserGroupListItemResponse(BaseModel):
    group_key: str
    aws_account_id: str | None = None
    asset_domain: str
    total_assets: int = 0
    k8s_assets: int = 0
    aws_assets: int = 0
    public_assets: int = 0
    entry_point_assets: int = 0
    crown_jewel_assets: int = 0


class UserGroupListResponse(BaseModel):
    items: list[UserGroupListItemResponse] = Field(default_factory=list)
    total: int = 0


class LoginRequest(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not normalized:
            raise ValueError("email must not be empty")
        return normalized

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("password must not be empty")
        return value


class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    user: UserSummaryResponse


class SignupRequest(BaseModel):
    email: str
    password: str
    name: str | None = None

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not normalized:
            raise ValueError("email must not be empty")
        return normalized

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("password must not be empty")
        return value


class SignupResponse(BaseModel):
    user: UserSummaryResponse



class ScanStartRequest(BaseModel):
    cluster_id: UUID = Field(
        ...,
        description="UUID of the cluster registered in DeployGuard",
        example="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    )
    request_source: RequestSource = Field(
        default="manual",
        description="Source of the cluster-level scan request",
        example="manual",
    )

    model_config = ConfigDict(json_schema_extra={"examples": [
        {
            "cluster_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
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
            "scans/prod-cluster-01/20260309T113020-k8s/k8s/k8s-snapshot.json",
            "scans/prod-cluster-01/20260309T113020-aws/aws/aws-snapshot.json",
        ],
    )

    model_config = ConfigDict(json_schema_extra={"examples": [
        {
            "files": [
                "scans/prod-cluster-01/20260309T113020-k8s/k8s/k8s-snapshot.json",
                "scans/prod-cluster-01/20260309T113020-aws/aws/aws-snapshot.json",
            ]
        }
    ]})

    @field_validator("files")
    @classmethod
    def validate_files_not_empty(cls, v: list) -> list:
        if not v:
            raise ValueError("files must not be empty")
        return v



class ScanStartItemResponse(BaseModel):
    scan_id: str = Field(..., description="생성된 스캔 세션 ID", example="20260309T113020-k8s")
    scanner_type: str = Field(..., description="생성된 스캐너 유형", example="k8s")
    status: str = Field(default=SCAN_STATUS_CREATED, description="스캔 세션 상태")

    model_config = ConfigDict(json_schema_extra={"examples": [
        {"scan_id": "20260309T113020-k8s", "scanner_type": "k8s", "status": "created"}
    ]})


class ScanStartResponse(BaseModel):
    cluster_id: str = Field(..., description="스캔 작업이 생성된 클러스터 ID")
    status: str = Field(default=SCAN_STATUS_CREATED, description="스캔 생성 요청 처리 상태")
    scans: list[ScanStartItemResponse] = Field(default_factory=list, description="생성된 pending scan_records 목록")

    model_config = ConfigDict(json_schema_extra={"examples": [
        {
            "cluster_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "status": "created",
            "scans": [
                {"scan_id": "20260309T113020-k8s", "scanner_type": "k8s", "status": "created"},
                {"scan_id": "20260309T113020-image", "scanner_type": "image", "status": "created"},
            ],
        }
    ]})


class UploadUrlResponse(BaseModel):
    upload_url: str = Field(..., description="S3 presigned PUT URL")
    s3_key: str = Field(
        ...,
        description="파일의 S3 오브젝트 키",
        example="scans/prod-cluster-01/20260309T113020-k8s/k8s/k8s-snapshot.json",
    )
    expires_in: int = Field(default=600, description="URL 만료 시간(초)")

    model_config = ConfigDict(json_schema_extra={"examples": [
        {
            "upload_url": "https://dg-raw-scans.s3.ap-northeast-2.amazonaws.com/scans/prod-cluster-01/20260309T113020-k8s/k8s/k8s-snapshot.json?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=...",
            "s3_key": "scans/prod-cluster-01/20260309T113020-k8s/k8s/k8s-snapshot.json",
            "expires_in": 600,
        }
    ]})


class ScanCompleteResponse(BaseModel):
    scan_id: str
    status: str = Field(default=SCAN_STATUS_COMPLETED, description="스캔 완료 상태")

    model_config = ConfigDict(json_schema_extra={"examples": [
        {"scan_id": "20260309T113020-k8s", "status": "completed"}
    ]})


class ScanFailResponse(BaseModel):
    scan_id: str
    status: str = Field(default=SCAN_STATUS_FAILED, description="스캔 실패 상태")

    model_config = ConfigDict(json_schema_extra={"examples": [
        {"scan_id": "20260309T113020-k8s", "status": "failed"}
    ]})


class ScanStatusResponse(BaseModel):
    scan_id: str
    cluster_id: str
    scanner_type: str
    status: str = Field(..., description="created | processing | uploading | completed | failed")
    created_at: datetime
    completed_at: datetime | None = None
    s3_keys: list[str] = Field(default_factory=list)

    model_config = ConfigDict(json_schema_extra={"examples": [
        {
            "scan_id": "20260309T113020-k8s",
            "cluster_id": "prod-cluster-01",
            "scanner_type": "k8s",
            "status": "created",
            "created_at": "2024-01-15T10:00:00Z",
            "completed_at": None,
            "s3_keys": [
                "scans/prod-cluster-01/20260309T113020-k8s/k8s/k8s-snapshot.json"
            ],
        }
    ]})


class ScanDetailResponse(BaseModel):
    scan_id: str
    cluster_id: str
    scanner_type: str
    status: str = Field(..., description="created | processing | uploading | completed | failed")
    created_at: datetime
    completed_at: datetime | None = None
    s3_keys: list[str] = Field(default_factory=list)

    model_config = ConfigDict(json_schema_extra={"examples": [
        {
            "scan_id": "20260309T113020-k8s",
            "cluster_id": "prod-cluster-01",
            "scanner_type": "k8s",
            "status": "completed",
            "created_at": "2024-01-15T10:00:00Z",
            "completed_at": "2024-01-15T10:30:00Z",
            "s3_keys": [
                "scans/prod-cluster-01/20260309T113020-k8s/k8s/k8s-snapshot.json"
            ],
        }
    ]})


class RawScanResultUrlResponse(BaseModel):
    scan_id: str
    s3_key: str
    download_url: str
    expires_in: int = Field(default=600, description="URL 만료 시간(초)")

    model_config = ConfigDict(json_schema_extra={"examples": [
        {
            "scan_id": "20260309T113020-k8s",
            "s3_key": "scans/prod-cluster-01/20260309T113020-k8s/k8s/k8s-snapshot.json",
            "download_url": "https://dg-raw-scans.s3.ap-northeast-2.amazonaws.com/scans/prod-cluster-01/20260309T113020-k8s/k8s/k8s-snapshot.json?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=...",
            "expires_in": 600,
        }
    ]})


class ScanSummaryItemResponse(BaseModel):
    scan_id: str
    scanner_type: str
    status: str = Field(..., description="created | processing | uploading | completed | failed")
    created_at: datetime
    completed_at: datetime | None = None
    file_count: int
    has_raw_result: bool

    model_config = ConfigDict(json_schema_extra={"examples": [
        {
            "scan_id": "20260309T113020-k8s",
            "scanner_type": "k8s",
            "status": "completed",
            "created_at": "2024-01-15T10:00:00Z",
            "completed_at": "2024-01-15T10:30:00Z",
            "file_count": 1,
            "has_raw_result": True,
        }
    ]})


class ClusterScanListResponse(BaseModel):
    items: list[ScanSummaryItemResponse] = Field(default_factory=list)
    total: int

    model_config = ConfigDict(json_schema_extra={"examples": [
        {
            "items": [
                {
                    "scan_id": "20260309T113020-k8s",
                    "scanner_type": "k8s",
                    "status": "completed",
                    "created_at": "2024-01-15T10:00:00Z",
                    "completed_at": "2024-01-15T10:30:00Z",
                    "file_count": 1,
                    "has_raw_result": True,
                }
            ],
            "total": 1,
        }
    ]})


class PendingScanClaimResponse(BaseModel):
    scan_id: str
    cluster_id: str
    scanner_type: str
    status: str = Field(default=SCAN_STATUS_PROCESSING, description="processing")
    claimed_by: str
    claimed_at: datetime
    started_at: datetime
    lease_expires_at: datetime
    files: list[str] = Field(default_factory=list)


class RuntimeUploadUrlResponse(BaseModel):
    upload_url: str = Field(..., description="Runtime snapshot S3 presigned PUT URL")
    s3_key: str = Field(
        ...,
        description="Runtime snapshot S3 object key",
        example="runtime/a1b2c3d4-e5f6-7890-abcd-ef1234567890/20260327T120000Z/events.json",
    )
    expires_in: int = Field(default=600, description="URL expiration in seconds")


class RuntimeCompleteRequest(BaseModel):
    s3_key: str = Field(
        ...,
        description="Uploaded runtime snapshot S3 key",
        example="runtime/a1b2c3d4-e5f6-7890-abcd-ef1234567890/20260327T120000Z/events.json",
    )
    snapshot_at: datetime = Field(..., description="Observed runtime snapshot timestamp")
    fact_count: int | None = Field(default=None, ge=0, description="Optional runtime fact count")


class RuntimeCompleteResponse(BaseModel):
    upload_id: str
    cluster_id: str
    s3_key: str
    snapshot_at: datetime
    uploaded_at: datetime
    fact_count: int | None = None


class RuntimeStatusResponse(BaseModel):
    cluster_id: str
    last_uploaded_at: datetime | None = None
    snapshot_at: datetime | None = None
    fact_count: int | None = None
    is_stale: bool


class RuntimeActivityItemResponse(BaseModel):
    snapshot_at: datetime
    observed_at: datetime
    source: str | None = None
    fact_type: str
    fact_family: str | None = None
    category: str | None = None
    action: str | None = None
    title: str
    summary: str
    severity: str | None = None
    notable: bool = False
    namespace: str | None = None
    pod_name: str | None = None
    service_account: str | None = None
    workload_name: str | None = None
    target: str | None = None
    target_type: str | None = None
    target_resource: str | None = None
    target_namespace: str | None = None
    success: bool | None = None
    response_code: int | None = None
    scenario_tags: list[str] = Field(default_factory=list)


class RuntimeActivityListResponse(BaseModel):
    cluster_id: str
    snapshot_count: int = 0
    items: list[RuntimeActivityItemResponse] = Field(default_factory=list)


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


class AttackGraphSeverity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    none = "none"


class AttackGraphNodeType(str, Enum):
    pod = "pod"
    service_account = "service_account"
    role = "role"
    cluster_role = "cluster_role"
    secret = "secret"
    service = "service"
    ingress = "ingress"
    node = "node"
    container_image = "container_image"
    iam_role = "iam_role"
    iam_user = "iam_user"
    s3_bucket = "s3_bucket"
    rds = "rds"
    security_group = "security_group"
    ec2_instance = "ec2_instance"
    unknown = "unknown"


class AttackGraphEdgeType(str, Enum):
    uses = "uses"
    bound_to = "bound_to"
    grants = "grants"
    escapes_to = "escapes_to"
    assumes = "assumes"
    accesses = "accesses"
    allows = "allows"
    runs = "runs"


class AttackGraphNodeResponse(BaseModel):
    id: str = Field(..., description="Stable node identifier")
    type: AttackGraphNodeType = Field(..., description="Canonical node type")
    label: str = Field(..., description="Backend-provided display label")
    severity: AttackGraphSeverity = Field(..., description="critical | high | medium | low | none")
    has_runtime_evidence: bool = Field(False, description="Runtime evidence attached")
    is_entry_point: bool = Field(False, description="Entry point flag")
    is_crown_jewel: bool = Field(False, description="Crown jewel flag")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional node metadata")


class AttackGraphEdgeResponse(BaseModel):
    id: str = Field(..., description="Stable edge identifier")
    source: str = Field(..., description="Source node id")
    target: str = Field(..., description="Target node id")
    type: AttackGraphEdgeType = Field(..., description="uses | bound_to | grants | escapes_to | assumes | accesses | allows | runs")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional edge metadata")


class AttackGraphPathResponse(BaseModel):
    id: str = Field(..., description="Stable path identifier")
    title: str = Field(..., description="Backend-provided path title")
    summary: str = Field("", description="Short human-readable path summary")
    severity: AttackGraphSeverity = Field(..., description="critical | high | medium | low | none")
    evidence_count: int = Field(0, description="Count of nodes or edges on the path with runtime evidence")
    node_ids: list[str] = Field(default_factory=list, description="Ordered node ids in the path")
    edge_ids: list[str] = Field(default_factory=list, description="Ordered edge ids in the path")


class AttackGraphResponse(BaseModel):
    cluster_id: str = Field(..., description="Cluster id")
    analysis_run_id: Optional[str] = Field(None, description="Latest analysis job id backing this graph")
    generated_at: Optional[datetime] = Field(None, description="Generation timestamp for the returned graph")
    nodes: list[AttackGraphNodeResponse] = Field(default_factory=list)
    edges: list[AttackGraphEdgeResponse] = Field(default_factory=list)
    paths: list[AttackGraphPathResponse] = Field(default_factory=list)


class AttackPathEdgeSequenceResponse(BaseModel):
    edge_id: str = Field(..., description="Stable persisted edge sequence id")
    edge_index: int = Field(..., description="0-based edge order within the attack path")
    source_node_id: str = Field(..., description="Source node id")
    target_node_id: str = Field(..., description="Target node id")
    edge_type: str = Field(..., description="Canonical persisted edge type")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Persisted edge metadata")


class AttackPathListItemResponse(BaseModel):
    path_id: str = Field(..., description="Stable path id")
    title: str = Field(..., description="Persisted path title")
    risk_level: AttackGraphSeverity = Field(..., description="critical | high | medium | low | none")
    risk_score: float | None = Field(None, description="Persisted normalized path risk score")
    raw_final_risk: float | None = Field(None, description="Persisted raw final path risk")
    hop_count: int = Field(0, description="Number of hops in the path")
    entry_node_id: str | None = Field(None, description="Entry point node id")
    target_node_id: str | None = Field(None, description="Crown jewel / target node id")
    node_ids: list[str] = Field(default_factory=list, description="Ordered path node ids")


class AttackPathDetailResponse(BaseModel):
    path_id: str = Field(..., description="Stable path id")
    title: str = Field(..., description="Persisted path title")
    risk_level: AttackGraphSeverity = Field(..., description="critical | high | medium | low | none")
    risk_score: float | None = Field(None, description="Persisted normalized path risk score")
    raw_final_risk: float | None = Field(None, description="Persisted raw final path risk")
    hop_count: int = Field(0, description="Number of hops in the path")
    entry_node_id: str | None = Field(None, description="Entry point node id")
    target_node_id: str | None = Field(None, description="Crown jewel / target node id")
    node_ids: list[str] = Field(default_factory=list, description="Ordered path node ids")
    edge_ids: list[str] = Field(default_factory=list, description="Ordered persisted edge ids")
    edges: list[AttackPathEdgeSequenceResponse] = Field(default_factory=list, description="Ordered persisted path edges")


class AttackPathListResponse(BaseModel):
    cluster_id: str = Field(..., description="Cluster id")
    analysis_run_id: Optional[str] = Field(None, description="Latest analysis job id backing these paths")
    generated_at: Optional[datetime] = Field(None, description="Generation timestamp for the returned paths")
    items: list[AttackPathListItemResponse] = Field(default_factory=list)


class AttackPathDetailEnvelopeResponse(BaseModel):
    cluster_id: str = Field(..., description="Cluster id")
    analysis_run_id: Optional[str] = Field(None, description="Latest analysis job id backing this path")
    generated_at: Optional[datetime] = Field(None, description="Generation timestamp for the returned path")
    path: Optional[AttackPathDetailResponse] = Field(None, description="Requested attack path detail")


class RemediationRecommendationListItemResponse(BaseModel):
    recommendation_id: str = Field(..., description="Stable recommendation id")
    recommendation_rank: int = Field(..., description="0-based greedy selection order")
    edge_source: str | None = Field(None, description="Source node id for the removable edge")
    edge_target: str | None = Field(None, description="Target node id for the removable edge")
    edge_type: str | None = Field(None, description="Persisted edge type")
    fix_type: str | None = Field(None, description="Persisted remediation fix type")
    fix_description: str | None = Field(None, description="Human-readable remediation description")
    blocked_path_ids: list[str] = Field(default_factory=list, description="Persisted blocked path ids")
    blocked_path_indices: list[int] = Field(default_factory=list, description="Persisted blocked path indices")
    fix_cost: float | None = Field(None, description="Persisted fix cost")
    edge_score: float | None = Field(None, description="Persisted greedy edge score")
    covered_risk: float | None = Field(None, description="Risk reduced by this recommendation alone")
    cumulative_risk_reduction: float | None = Field(None, description="Running cumulative risk reduction through this rank")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Persisted recommendation metadata")
    llm_explanation: str | None = None
    llm_provider: str | None = None
    llm_model: str | None = None
    llm_status: str | None = "not_generated"
    llm_generated_at: datetime | None = None
    llm_error_message: str | None = None


class RemediationRecommendationDetailResponse(BaseModel):
    recommendation_id: str = Field(..., description="Stable recommendation id")
    recommendation_rank: int = Field(..., description="0-based greedy selection order")
    edge_source: str | None = Field(None, description="Source node id for the removable edge")
    edge_target: str | None = Field(None, description="Target node id for the removable edge")
    edge_type: str | None = Field(None, description="Persisted edge type")
    fix_type: str | None = Field(None, description="Persisted remediation fix type")
    fix_description: str | None = Field(None, description="Human-readable remediation description")
    blocked_path_ids: list[str] = Field(default_factory=list, description="Persisted blocked path ids")
    blocked_path_indices: list[int] = Field(default_factory=list, description="Persisted blocked path indices")
    fix_cost: float | None = Field(None, description="Persisted fix cost")
    edge_score: float | None = Field(None, description="Persisted greedy edge score")
    covered_risk: float | None = Field(None, description="Risk reduced by this recommendation alone")
    cumulative_risk_reduction: float | None = Field(None, description="Running cumulative risk reduction through this rank")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Persisted recommendation metadata")
    llm_explanation: str | None = None
    llm_provider: str | None = None
    llm_model: str | None = None
    llm_status: str | None = "not_generated"
    llm_generated_at: datetime | None = None
    llm_error_message: str | None = None


class RemediationRecommendationListResponse(BaseModel):
    cluster_id: str = Field(..., description="Cluster id")
    analysis_run_id: Optional[str] = Field(None, description="Latest analysis job id backing these recommendations")
    generated_at: Optional[datetime] = Field(None, description="Generation timestamp for the returned recommendations")
    items: list[RemediationRecommendationListItemResponse] = Field(default_factory=list)


class RemediationRecommendationDetailEnvelopeResponse(BaseModel):
    cluster_id: str = Field(..., description="Cluster id")
    analysis_run_id: Optional[str] = Field(None, description="Latest analysis job id backing this recommendation")
    generated_at: Optional[datetime] = Field(None, description="Generation timestamp for the returned recommendation")
    recommendation: Optional[RemediationRecommendationDetailResponse] = Field(
        None, description="Requested remediation recommendation detail"
    )


class ExplanationProviderName(str, Enum):
    openai = "openai"
    xai = "xai"


class RecommendationExplanationRequest(BaseModel):
    provider: ExplanationProviderName | None = Field(
        None,
        description="Optional provider override",
    )
    model: str | None = Field(
        None,
        description="Optional model override for the selected provider",
    )


class RecommendationExplanationResponse(BaseModel):
    cluster_id: str
    recommendation_id: str
    explanation_status: str
    used_llm: bool
    base_explanation: str
    final_explanation: str
    provider: str | None = None
    model: str | None = None
    fallback_reason: str | None = None


class LLMProviderConfigUpsertRequest(BaseModel):
    api_key: str = Field(..., description="Provider API key")
    is_active: bool = Field(..., description="Whether this provider config should be active")
    default_model: str | None = Field(None, description="Optional default model override")

    @field_validator("api_key")
    @classmethod
    def validate_api_key(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("api_key must not be empty")
        return normalized


class LLMProviderConfigResponse(BaseModel):
    provider: str
    is_active: bool
    default_model: str | None = None
    has_api_key: bool
    created_at: datetime
    updated_at: datetime


class LLMProviderConfigListResponse(BaseModel):
    items: list[LLMProviderConfigResponse] = Field(default_factory=list)


class AnalysisResultStatsGraphResponse(BaseModel):
    nodes: int
    edges: int
    entry_points: int
    crown_jewels: int


class AnalysisResultStatsPathsResponse(BaseModel):
    total: int
    returned: int


class AnalysisResultStatsFactsResponse(BaseModel):
    total: int


class AnalysisResultStatsResponse(BaseModel):
    facts: AnalysisResultStatsFactsResponse | None = None
    graph: AnalysisResultStatsGraphResponse | None = None
    paths: AnalysisResultStatsPathsResponse | None = None


class AnalysisResultResponse(BaseModel):
    job: AnalysisJobDetailResponse
    summary: AnalysisResultSummaryResponse
    attack_paths_preview: list[AttackPathListItemResponse] = Field(default_factory=list)
    remediation_preview: list[RemediationRecommendationListItemResponse] = Field(default_factory=list)
    attack_paths: list[AttackPathDetailResponse] = Field(default_factory=list)
    remediation_recommendations: list[RemediationRecommendationDetailResponse] = Field(default_factory=list)
    links: AnalysisResultLinksResponse
    stats: AnalysisResultStatsResponse | None = None


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


# =============================================================================
# 신규 Asset Inventory View API 스키마 (v1)
# 기존 스키마와 완전 분리 — prefix: InventoryView*
# 기존 InventorySummaryResponse, AssetInventoryItemResponse 등 수정 없음
# =============================================================================

class InvScannerCoverageStatus(str, Enum):
    """scan_records 기반 근사 커버리지 상태 (MVP)"""
    covered = "covered"
    partial = "partial"
    not_covered = "not_covered"


# ---------- Scanner Status ----------

class InvScannerItem(BaseModel):
    """스캐너별 최신 스캔 상태"""
    scanner_type: str = Field(..., description="k8s | aws | image")
    display_name: str = Field(..., description="UI 표시명. 예: K8s Scanner (DG-K8s)")
    status: str = Field(..., description="active | inactive")
    last_scan_at: Optional[datetime] = Field(None, description="마지막 completed 스캔 시각 (scan_records 기준)")
    scan_id: Optional[str] = Field(None, description="마지막 completed scan_id")
    coverage_status: InvScannerCoverageStatus = Field(
        ...,
        description="covered: completed scan 존재 / not_covered: 없음 (MVP 근사값)",
    )
    resources_collected: Optional[int] = Field(
        None,
        description="수집된 리소스 수. 현재 단계에서는 null 허용 (TODO: scan result 연동 후 채움)",
    )


class InvScannerStatusResponse(BaseModel):
    """GET /inventory/scanner-status 응답"""
    scanners: List[InvScannerItem]


# ---------- Summary ----------

class InvScannerCoverageDetail(BaseModel):
    """Summary 내 스캐너별 커버리지 상세"""
    status: InvScannerCoverageStatus
    last_scan_at: Optional[datetime] = None
    scan_id: Optional[str] = None


class InvRiskSummary(BaseModel):
    """
    위험 요약.
    MVP: graph_nodes / attack_paths 테이블 미연동으로 전부 0.
    TODO: GraphSnapshot → graph_nodes / attack_paths 연동 후 실값 채움.
    """
    entry_point_count: int = Field(0, description="[임시값] graph_nodes.is_entry_point=true 개수")
    crown_jewel_count: int = Field(0, description="[임시값] graph_nodes.is_crown_jewel=true 개수")
    critical_path_count: int = Field(0, description="[임시값] attack_paths critical 개수")


class InvSummaryResponse(BaseModel):
    """GET /inventory/summary 응답"""
    cluster_id: str
    cluster_name: str
    last_analysis_at: Optional[datetime] = Field(
        None,
        description="최신 graph_snapshot 기준 분석 완료 시각. MVP: graph 미연동으로 null.",
    )
    total_node_count: int = Field(..., description="전체 자산 수 (snapshot 기반)")
    k8s_resources: Dict[str, int] = Field(
        default_factory=dict,
        description="K8s 자산 타입별 카운트. MVP: snapshot 없으면 빈 dict.",
    )
    aws_resources: Dict[str, int] = Field(
        default_factory=dict,
        description="AWS 자산 타입별 카운트. snapshot raw_result_json 기반.",
    )
    scanner_coverage: Dict[str, InvScannerCoverageDetail] = Field(
        default_factory=dict,
        description="scanner_type → 커버리지 상세. scan_records 기반 근사값 (MVP).",
    )
    risk_summary: InvRiskSummary = Field(
        default_factory=InvRiskSummary,
        description="위험 요약. MVP: graph 미연동으로 전부 0 (임시값).",
    )


# ---------- Assets ----------

class InvAssetItem(BaseModel):
    """자산 목록 단일 아이템"""
    node_id: str = Field(..., description="자산 식별자. 예: ec2:i-0abc123 / pod:prod/web-abc")
    node_type: str = Field(..., description="ec2 | s3 | rds | iam_role | iam_user | pod | service | ...")
    domain: str = Field(..., description="k8s | aws")
    name: str
    namespace: Optional[str] = Field(None, description="K8s 자산만 해당. AWS는 null.")
    account_id: Optional[str] = Field(None, description="AWS 자산만 해당. K8s는 null.")
    region: Optional[str] = Field(None, description="AWS 자산 중 region 있는 것만 해당.")
    is_entry_point: bool = Field(False, description="[임시값] graph 미연동. 항상 false (MVP).")
    is_crown_jewel: bool = Field(False, description="[임시값] graph 미연동. 항상 false (MVP).")
    base_risk: Optional[int] = Field(None, description="[임시값] graph 미연동. null (MVP).")
    scanner_coverage: Dict[str, str] = Field(
        default_factory=dict,
        description="scanner_type → covered | not_covered. node_type 기반 매핑 + scan_records 근사.",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="원본 API에서 가져온 자산 상세 속성 (raw_result_json 기반).",
    )
    timestamps: Dict[str, Optional[str]] = Field(
        default_factory=dict,
        description="last_scan_at: scan_records 기준 / last_analysis_at: graph 기준 (MVP: null).",
    )


class InvAssetListResponse(BaseModel):
    """GET /inventory/assets 응답"""
    graph_id: Optional[str] = Field(
        None,
        description="기준 graph_snapshot id. MVP: graph 미연동으로 null.",
    )
    total_count: int
    page: int
    page_size: int
    assets: List[InvAssetItem]


# ---------- Risk Spotlight ----------

class InvRiskSpotlightItem(BaseModel):
    """Entry Point 또는 Crown Jewel 단일 아이템"""
    node_id: str
    node_type: str
    domain: str
    name: str
    namespace: Optional[str] = None
    base_risk: Optional[int] = Field(None, description="[임시값] graph 미연동. null (MVP).")
    attack_path_count: int = Field(0, description="[임시값] attack_paths 미연동. 0 (MVP).")
    reachable_crown_jewel_count: Optional[int] = Field(
        None,
        description="Entry Point 전용. Crown Jewel 미연동으로 null (MVP).",
    )


class InvRiskSpotlightResponse(BaseModel):
    """GET /inventory/risk-spotlight 응답"""
    graph_id: Optional[str] = Field(
        None,
        description="기준 graph_snapshot id. MVP: null.",
    )
    entry_points: List[InvRiskSpotlightItem] = Field(
        default_factory=list,
        description="[임시값] graph_nodes.is_entry_point 미연동. 빈 배열 (MVP).",
    )
    crown_jewels: List[InvRiskSpotlightItem] = Field(
        default_factory=list,
        description="[임시값] graph_nodes.is_crown_jewel 미연동. 빈 배열 (MVP).",
    )


class CloudTrailEvent(BaseModel):
    event_id: str
    event_time: datetime
    event_name: str
    event_source: str
    source_ip: str | None = None
    user_identity_type: str | None = None
    user_identity_arn: str | None = None
    request_parameters: dict | None = None
    error_code: str | None = None
    error_message: str | None = None


class CloudTrailEventListResponse(BaseModel):
    scanned_at: datetime
    hours: int
    total: int
    items: list[CloudTrailEvent] = Field(default_factory=list)
