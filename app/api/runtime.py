"""
Runtime snapshot direct upload API endpoints.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query, status

from app.api.auth import get_authenticated_cluster, get_current_user
from app.application.di import get_runtime_snapshot_service
from app.application.services.runtime_snapshot_service import RuntimeSnapshotService
from app.models.schemas import (
    RuntimeActivityListResponse,
    ClusterResponse,
    RuntimeCompleteRequest,
    RuntimeCompleteResponse,
    RuntimeStatusResponse,
    RuntimeUploadUrlResponse,
    UserSummaryResponse,
)


router = APIRouter(prefix="/api/v1", tags=["Runtime"])


@router.post(
    "/runtime/upload-url",
    response_model=RuntimeUploadUrlResponse,
    status_code=status.HTTP_200_OK,
)
async def create_runtime_upload_url(
    authenticated_cluster: ClusterResponse = Depends(get_authenticated_cluster),
    service: RuntimeSnapshotService = Depends(get_runtime_snapshot_service),
):
    return await service.get_upload_url(authenticated_cluster_id=authenticated_cluster.id)


@router.post(
    "/runtime/complete",
    response_model=RuntimeCompleteResponse,
    status_code=status.HTTP_200_OK,
)
async def complete_runtime_upload(
    request: RuntimeCompleteRequest,
    authenticated_cluster: ClusterResponse = Depends(get_authenticated_cluster),
    service: RuntimeSnapshotService = Depends(get_runtime_snapshot_service),
):
    return await service.complete_upload(
        authenticated_cluster_id=authenticated_cluster.id,
        s3_key=request.s3_key,
        snapshot_at=request.snapshot_at,
        fact_count=request.fact_count,
    )


@router.get(
    "/clusters/{cluster_id}/runtime/status",
    response_model=RuntimeStatusResponse,
    status_code=status.HTTP_200_OK,
)
async def get_runtime_status(
    cluster_id: str,
    current_user: UserSummaryResponse = Depends(get_current_user),
    service: RuntimeSnapshotService = Depends(get_runtime_snapshot_service),
):
    return await service.get_status(cluster_id=cluster_id, user_id=current_user.id)


@router.get(
    "/clusters/{cluster_id}/runtime/activities",
    response_model=RuntimeActivityListResponse,
    status_code=status.HTTP_200_OK,
)
async def get_runtime_activities(
    cluster_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    snapshot_limit: int = Query(default=1, ge=1, le=20),
    current_user: UserSummaryResponse = Depends(get_current_user),
    service: RuntimeSnapshotService = Depends(get_runtime_snapshot_service),
):
    return await service.get_activities(
        cluster_id=cluster_id,
        user_id=current_user.id,
        limit=limit,
        snapshot_limit=snapshot_limit,
    )


from app.models.schemas import CloudTrailEventListResponse


@router.get(
    "/cloudtrail/events",
    response_model=CloudTrailEventListResponse,
    status_code=status.HTTP_200_OK,
)
async def get_cloudtrail_events(
    hours: int = Query(default=24, ge=1, le=168),
    event_name: str | None = Query(default=None),
    only_errors: bool = Query(default=False),
    current_user: UserSummaryResponse = Depends(get_current_user),
):
    import gzip
    import json
    from datetime import datetime, timedelta, timezone

    import boto3
    from fastapi import HTTPException
    from botocore.exceptions import BotoCoreError, ClientError

    del current_user

    role_arn = "arn:aws:iam::244105859679:role/DeployGuardCloudTrailReadRole"
    role_session_name = "deployguard-session"
    bucket_name = "aws-cloudtrail-logs-244105859679-27b511bb"
    base_prefix = "AWSLogs/244105859679/CloudTrail/ap-northeast-2/"
    whitelist = {
        "ConsoleLogin",
        "CreateUser",
        "DeleteUser",
        "AttachUserPolicy",
        "DetachUserPolicy",
        "PutUserPolicy",
        "CreateAccessKey",
        "DeleteAccessKey",
        "UpdateAssumeRolePolicy",
        "PutRolePolicy",
        "CreateRole",
        "DeleteRole",
        "GetSecretValue",
        "PutSecretValue",
        "RunInstances",
        "TerminateInstances",
        "DeleteBucket",
        "PutBucketPolicy",
        "PutBucketAcl",
        "UpdateFunctionCode",
        "UpdateFunctionConfiguration",
        "AuthorizationFailure",
    }

    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=hours)

    try:
        sts_client = boto3.client("sts")
        assumed = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=role_session_name,
        )
    except (ClientError, BotoCoreError) as exc:
        raise HTTPException(status_code=500, detail=f"Failed to assume CloudTrail read role: {exc}") from exc

    credentials = assumed["Credentials"]
    s3_client = boto3.client(
        "s3",
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        region_name="ap-northeast-2",
    )

    prefixes: set[str] = set()
    cursor = since
    while cursor <= now:
        prefixes.add(f"{base_prefix}{cursor.strftime('%Y/%m/%d/')}")
        cursor += timedelta(hours=1)
    prefixes.add(f"{base_prefix}{now.strftime('%Y/%m/%d/')}")

    items: list[dict] = []
    for prefix in sorted(prefixes):
        continuation_token = None
        while True:
            list_kwargs = {"Bucket": bucket_name, "Prefix": prefix}
            if continuation_token:
                list_kwargs["ContinuationToken"] = continuation_token

            try:
                response = s3_client.list_objects_v2(**list_kwargs)
            except (ClientError, BotoCoreError):
                break

            contents = response.get("Contents", [])
            for obj in contents:
                key = obj.get("Key")
                if not isinstance(key, str) or not key.endswith(".json.gz"):
                    continue

                try:
                    body = s3_client.get_object(Bucket=bucket_name, Key=key)["Body"].read()
                    payload = json.loads(gzip.decompress(body).decode("utf-8"))
                except (ClientError, BotoCoreError, OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError):
                    continue

                records = payload.get("Records", [])
                if not isinstance(records, list):
                    continue

                for record in records:
                    if not isinstance(record, dict):
                        continue

                    record_event_name = record.get("eventName")
                    record_error_code = record.get("errorCode")
                    if record_error_code == "Client.DryRunOperation":
                        continue

                    user_identity = record.get("userIdentity")
                    if not isinstance(user_identity, dict):
                        user_identity = {}
                    user_identity_type = user_identity.get("type")

                    include_assume_role = (
                        record_event_name == "AssumeRole"
                        and user_identity_type in {"AWSAccount", "IAMUser"}
                    )

                    if record_error_code is None and record_event_name not in whitelist and not include_assume_role:
                        continue
                    if event_name is not None and record_event_name != event_name:
                        continue
                    if only_errors and record_error_code is None:
                        continue

                    event_time_raw = record.get("eventTime")
                    if not isinstance(event_time_raw, str):
                        continue

                    try:
                        event_time = datetime.fromisoformat(event_time_raw.replace("Z", "+00:00")).astimezone(timezone.utc)
                    except ValueError:
                        continue

                    if event_time < since:
                        continue

                    request_parameters = record.get("requestParameters")
                    if not isinstance(request_parameters, dict):
                        request_parameters = None

                    items.append(
                        {
                            "event_id": record.get("eventID"),
                            "event_time": event_time,
                            "event_name": record_event_name,
                            "event_source": record.get("eventSource"),
                            "source_ip": record.get("sourceIPAddress"),
                            "user_identity_type": user_identity_type,
                            "user_identity_arn": user_identity.get("arn"),
                            "request_parameters": request_parameters,
                            "error_code": record_error_code,
                            "error_message": record.get("errorMessage"),
                        }
                    )

            if not response.get("IsTruncated"):
                break
            continuation_token = response.get("NextContinuationToken")

    items = [
        item
        for item in items
        if isinstance(item.get("event_id"), str)
        and isinstance(item.get("event_name"), str)
        and isinstance(item.get("event_source"), str)
    ]
    items.sort(key=lambda item: item["event_time"], reverse=True)

    return {
        "scanned_at": now,
        "hours": hours,
        "total": len(items),
        "items": items,
    }
