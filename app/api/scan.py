"""
Scan data ingestion endpoints.
"""
import logging

from fastapi import APIRouter, Depends, Query, Request, Response
from app.models.schemas import (
    ClusterScanListResponse,
    RawScanResultUrlResponse,
    ScanStartRequest, ScanStartResponse,
    UploadUrlRequest, UploadUrlResponse,
    ScanCompleteRequest, ScanCompleteResponse,
    ScanFailResponse,
    ScanDetailResponse,
    ScanStatusResponse,
    PendingScanClaimResponse,
    ScannerType,
    ClusterResponse,
)
from app.application.di import get_scan_service
from app.application.services.scan_service import ScanService
from app.api.auth import get_authenticated_cluster, get_current_user
from app.models.schemas import UserSummaryResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/scans", tags=["Scans"])
cluster_router = APIRouter(prefix="/api/v1/clusters", tags=["Scans"])


@router.post(
    "/start",
    response_model=ScanStartResponse,
    status_code=201,
    summary="스캔 작업 큐 생성",
    description="""
대시보드 또는 스케줄러가 호출하여 `created` 상태의 스캔 작업을 생성하는 작업 등록 API입니다.
이 엔드포인트는 스캔을 직접 실행하지 않으며, 워커가 이후 `/pending`을 폴링해 claim할 작업만 등록합니다.
응답에는 생성된 스캔 작업 목록이 포함되며, 이후 `upload-url` 및 `complete` 호출에 사용됩니다.

**실제 동작 흐름:**
1. 대시보드 또는 스케줄러가 `/start`를 호출해 클러스터 타입 기준 큐 작업을 생성합니다.
2. 스캐너 워커가 `/pending`을 폴링해 자신이 처리할 created 작업을 claim합니다.
3. claim에 성공한 워커가 실제 스캔을 수행한 뒤 결과를 업로드하고 `/complete`를 호출합니다.

**클러스터 타입별 fan-out:**
- `eks`, `self-managed` → `k8s` + `image`
- `aws` → `aws`

클러스터와 scanner_type 조합당 하나의 활성 스캔만 허용합니다.
fan-out 대상 중 하나라도 활성 상태(`created`, `processing`, `uploading`)가 이미 있으면 전체 요청은 409로 거부됩니다.
""",
    responses={
        201: {"description": "클러스터 타입에 맞는 스캔 세션이 성공적으로 생성되었습니다"},
        404: {"description": "클러스터를 찾을 수 없습니다"},
        409: {"description": "fan-out 대상 스캐너 중 하나 이상에 대해 활성 스캔이 이미 존재합니다"},
        422: {"description": "유효하지 않은 request_source 또는 필드 누락"},
    },
)
async def start_scan(
    request: ScanStartRequest,
    http_request: Request,
    service: ScanService = Depends(get_scan_service),
    current_user: UserSummaryResponse = Depends(get_current_user),
):
    request_id = getattr(http_request.state, "request_id", None)
    logger.info(
        "scan.start.request_received",
        extra={
            "request_id": request_id,
            "cluster_id": str(request.cluster_id),
            "request_source": request.request_source,
        },
    )
    return await service.start_scan(
        cluster_id=request.cluster_id,
        request_source=request.request_source,
        user_id=current_user.id,
        request_id=request_id,
        endpoint_path=http_request.url.path,
    )


@router.get(
    "/pending",
    response_model=PendingScanClaimResponse,
    status_code=200,
    summary="워커용 created 작업 클레임",
    description="""
스캐너 워커가 폴링하여 자신이 실제로 실행할 created 작업 1건을 claim하는 워커 클레임 API입니다.
`Authorization: Bearer <api_token>` 인증이 필요합니다.
클러스터는 요청 파라미터가 아니라 인증 토큰으로 식별됩니다.
`/start`가 생성한 작업만 이 엔드포인트에서 claim 대상이 됩니다.
토큰 클러스터 + `scanner_type`에 대해 `created` 작업만 대상으로 하며, 클레임은 원자적으로 수행됩니다.
성공 시 상태는 `processing`으로 전이되고 `claimed_at`, `claimed_by`, `started_at`, `lease_expires_at`이 설정됩니다.
""",
    responses={
        200: {"description": "클레임된 스캔 작업 반환"},
        204: {"description": "클레임 가능한 created 스캔이 없음"},
        401: {"description": "Authorization 헤더 누락/형식 오류"},
        403: {"description": "유효하지 않은 scanner API token"},
    },
)
async def claim_pending_scan(
    request: Request,
    scanner_type: ScannerType,
    claimed_by: str | None = Query(default=None, min_length=1),
    lease_seconds: int = Query(default=300, ge=1),
    service: ScanService = Depends(get_scan_service),
    authenticated_cluster: ClusterResponse = Depends(get_authenticated_cluster),
):
    request_id = getattr(request.state, "request_id", None)
    logger.info(
        "scan.pending.poll_received",
        extra={
            "request_id": request_id,
            "cluster_id": authenticated_cluster.id,
            "scanner_type": scanner_type.value,
            "claimed_by": claimed_by or "unknown-worker",
        },
    )
    record = await service.claim_pending_scan(
        cluster_id=authenticated_cluster.id,
        scanner_type=scanner_type,
        claimed_by=claimed_by,
        lease_seconds=lease_seconds,
        request_id=request_id,
    )
    if record is None:
        return Response(status_code=204)
    return PendingScanClaimResponse(
        scan_id=record.scan_id,
        cluster_id=record.cluster_id,
        scanner_type=record.scanner_type,
        status=record.status,
        claimed_by=record.claimed_by,
        claimed_at=record.claimed_at,
        started_at=record.started_at,
        lease_expires_at=record.lease_expires_at,
        files=record.s3_keys or [],
    )


@router.post(
    "/{scan_id}/upload-url",
    response_model=UploadUrlResponse,
    status_code=200,
    summary="파일 업로드용 presigned URL 발급",
    description="""
스캔 결과 파일을 업로드하기 위한 S3 presigned PUT URL을 생성합니다.
`Authorization: Bearer <api_token>` 인증이 필요합니다.

클라이언트는 다음 순서로 진행해야 합니다:
1. `/pending`으로 created 작업을 claim하여 processing 상태로 전이합니다
2. 이 엔드포인트를 호출하여 presigned URL을 발급받습니다
3. 반환된 URL을 사용하여 파일을 S3에 직접 PUT합니다
4. 여러 파일을 업로드해야 하는 경우 각 파일마다 반복합니다
5. 모든 파일 업로드가 완료되면 `/complete`를 호출합니다

Presigned URL은 600초(10분) 후 만료됩니다.

**S3 키 형식:** `scans/{cluster_id}/{scan_id}/{scanner_type}/{scanner_type}-snapshot.json`

`scanner_type`은 스캔 세션에 의해 결정됩니다 (`/start` 호출 시 설정).
각 스캐너는 canonical raw snapshot 파일명으로 기록합니다. 유효한 스캐너 유형: `k8s`, `aws`, `image`.

**예시:**
- `scans/prod-cluster/scan123/k8s/k8s-snapshot.json`
- `scans/prod-cluster/scan123/aws/aws-snapshot.json`
- `scans/prod-cluster/scan123/image/image-snapshot.json`
""",
    responses={
        200: {"description": "Presigned URL이 생성되었습니다"},
        404: {"description": "스캔 세션을 찾을 수 없습니다"},
        409: {"description": "스캔 세션 상태에서 업로드를 허용하지 않습니다"},
        401: {"description": "Authorization 헤더 누락/형식 오류"},
        403: {"description": "유효하지 않은 scanner API token"},
    },
)
async def get_upload_url(
    request_context: Request,
    scan_id: str,
    request: UploadUrlRequest,
    service: ScanService = Depends(get_scan_service),
    _: ClusterResponse = Depends(get_authenticated_cluster),
):
    return await service.get_upload_url(
        scan_id=scan_id,
        file_name=request.file_name,
        request_id=getattr(request_context.state, "request_id", None),
        endpoint_path=request_context.url.path,
    )


@router.post(
    "/{scan_id}/complete",
    response_model=ScanCompleteResponse,
    status_code=202,
    summary="스캐너 완료(업로드 완료) 알림",
    description="""
스캐너가 파일 업로드를 마친 뒤 호출하는 완료 알림 엔드포인트입니다.
`Authorization: Bearer <api_token>` 인증이 필요합니다.
요청한 스캔이 인증된 클러스터 소유인지 검증하며, 불일치 시 거부합니다.
동작은 다음과 같습니다:
1. 업로드된 S3 파일 존재 여부 검증
2. 상태를 `processing` 또는 `uploading`에서 `completed`로 전이
3. 분석 작업 생성은 하지 않음. 이후 사용자가 별도로 `POST /api/v1/analysis/jobs`를 호출해야 함

즉, complete는 스캔 완료를 기록하는 역할만 하며 분석 파이프라인 실행 자체를 수행하지 않습니다.
""",
    responses={
        202: {"description": "스캔 완료가 접수되었으며 completed 상태로 전이되었습니다"},
        400: {"description": "S3에서 하나 이상의 파일을 찾을 수 없습니다"},
        404: {"description": "스캔 세션을 찾을 수 없습니다"},
        409: {"description": "현재 상태에서는 complete 처리할 수 없습니다"},
        401: {"description": "Authorization 헤더 누락/형식 오류"},
        403: {"description": "유효하지 않은 scanner API token 또는 스캔 소유권 불일치"},
    },
)
async def complete_scan(
    request_context: Request,
    scan_id: str,
    request: ScanCompleteRequest,
    service: ScanService = Depends(get_scan_service),
    authenticated_cluster: ClusterResponse = Depends(get_authenticated_cluster),
):
    request_id = getattr(request_context.state, "request_id", None)
    logger.info(
        "scan.complete.request_received",
        extra={
            "request_id": request_id,
            "scan_id": scan_id,
            "cluster_id": authenticated_cluster.id,
        },
    )
    return await service.complete_scan(
        scan_id=scan_id,
        files=request.files,
        authenticated_cluster_id=authenticated_cluster.id,
        request_id=request_id,
        endpoint_path=request_context.url.path,
    )


@router.post(
    "/{scan_id}/fail",
    response_model=ScanFailResponse,
    status_code=202,
    summary="스캔 세션 실패 처리",
    description="""
스캔 세션을 수동으로 `failed` 상태로 전이합니다.

- `created`, `processing`, `uploading` 상태는 `failed`로 전이됩니다.
- `completed`, `failed` 상태는 idempotent success로 처리됩니다.
""",
    responses={
        202: {"description": "스캔 실패 처리가 접수되었습니다"},
        404: {"description": "스캔 세션을 찾을 수 없습니다"},
    },
)
async def fail_scan(
    request_context: Request,
    scan_id: str,
    service: ScanService = Depends(get_scan_service),
):
    request_id = getattr(request_context.state, "request_id", None)
    logger.info(
        "scan.fail.request_received",
        extra={
            "request_id": request_id,
            "scan_id": scan_id,
            "endpoint_path": request_context.url.path,
            "failure_source": "manual",
        },
    )
    return await service.fail_scan(
        scan_id=scan_id,
        request_id=request_id,
        endpoint_path=request_context.url.path,
    )


@cluster_router.get(
    "/{cluster_id}/scans",
    response_model=ClusterScanListResponse,
    status_code=200,
    summary="클러스터 스캔 이력 조회",
    description="""
클러스터에 속한 스캔 세션 목록을 최신순으로 조회합니다.

각 항목에는 스캐너 유형, 상태, 생성/완료 시각과 원본 결과 파일 존재 여부가 포함됩니다.
""",
    responses={
        200: {"description": "클러스터 스캔 이력"},
    },
)
async def list_cluster_scans(
    cluster_id: str,
    service: ScanService = Depends(get_scan_service),
    current_user: UserSummaryResponse = Depends(get_current_user),
):
    return await service.list_cluster_scans(cluster_id=cluster_id, user_id=current_user.id)


@router.get(
    "/{scan_id}",
    response_model=ScanDetailResponse,
    status_code=200,
    summary="스캔 세션 상세 조회",
    description="""
스캔 세션의 메타데이터를 조회합니다.

반환값에는 스캔 식별자, 클러스터, scanner_type, 상태, 생성/완료 시각과
저장된 S3 키 목록이 포함됩니다.
""",
    responses={
        200: {"description": "스캔 세션 상세"},
        404: {"description": "스캔 세션을 찾을 수 없습니다"},
    },
)
async def get_scan_detail(
    scan_id: str,
    service: ScanService = Depends(get_scan_service),
    current_user: UserSummaryResponse = Depends(get_current_user),
):
    return await service.get_scan_detail(scan_id=scan_id, user_id=current_user.id)


@router.get(
    "/{scan_id}/raw-result-url",
    response_model=RawScanResultUrlResponse,
    status_code=200,
    summary="원본 스캔 결과 다운로드 URL 조회",
    description="""
스캔에 저장된 원본 결과 파일 1건에 대한 presigned download URL을 반환합니다.

현재는 저장된 S3 키가 정확히 1개인 경우에만 URL을 생성합니다.
""",
    responses={
        200: {"description": "원본 스캔 결과 다운로드 URL"},
        404: {"description": "스캔 세션 또는 원본 결과 파일을 찾을 수 없습니다"},
        409: {"description": "원본 결과 파일이 여러 개라 기본 선택 규칙이 없습니다"},
    },
)
async def get_raw_result_download_url(scan_id: str, service: ScanService = Depends(get_scan_service)):
    return await service.get_raw_result_download_url(scan_id=scan_id)


@router.get(
    "/{scan_id}/status",
    response_model=ScanStatusResponse,
    status_code=200,
    summary="스캔 세션 상태 조회",
    description="""
스캔 세션의 현재 상태를 확인합니다.

**상태 값:**
- `created` — 스캔 요청이 생성됨
- `processing` — 워커가 스캔을 실행 중
- `uploading` — 하나 이상의 업로드 URL이 요청됨
- `completed` — 스캔 업로드 검증까지 완료됨
- `failed` — 스캔 실행 또는 업로드 검증 실패
""",
    responses={
        200: {"description": "스캔 세션 상태"},
        404: {"description": "스캔 세션을 찾을 수 없습니다"},
    },
)
async def get_scan_status(
    scan_id: str,
    service: ScanService = Depends(get_scan_service),
    current_user: UserSummaryResponse = Depends(get_current_user),
):
    return await service.get_scan_status(scan_id=scan_id, user_id=current_user.id)
