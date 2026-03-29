"""
Application service for runtime snapshot direct uploads.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import re
from typing import Any

from fastapi import HTTPException

from app.config import settings
from app.domain.repositories.cluster_repository import ClusterRepository
from app.domain.repositories.runtime_snapshot_repository import RuntimeSnapshotRepository
from app.models.schemas import (
    RuntimeActivityItemResponse,
    RuntimeActivityListResponse,
    RuntimeCompleteResponse,
    RuntimeStatusResponse,
    RuntimeUploadUrlResponse,
)


_RUNTIME_KEY_PATTERN = re.compile(
    r"^runtime/(?P<cluster_id>[^/]+)/(?P<timestamp>\d{8}T\d{6}Z)/events\.json$"
)


class RuntimeSnapshotService:
    _TITLE_BY_FACT_TYPE = {
        "secret_read": "Secret access detected",
        "sa_token_access": "Service account token access detected",
        "host_sensitive_path_access": "Sensitive host path access detected",
        "imds_access": "Instance metadata access detected",
        "pod_exec": "Pod exec activity detected",
        "rolebinding_create": "RoleBinding creation detected",
        "network_connect": "Network connection observed",
        "suspicious_process": "Suspicious process execution detected",
    }

    def __init__(
        self,
        runtime_snapshot_repository: RuntimeSnapshotRepository,
        cluster_repository: ClusterRepository,
        s3_service,
    ):
        self._repo = runtime_snapshot_repository
        self._clusters = cluster_repository
        self._s3 = s3_service

    async def get_upload_url(self, authenticated_cluster_id: str) -> RuntimeUploadUrlResponse:
        uploaded_at = datetime.now(timezone.utc)
        upload_url, s3_key = self._s3.generate_runtime_presigned_upload_url(
            cluster_id=authenticated_cluster_id,
            uploaded_at=uploaded_at,
            expires_in=600,
        )
        return RuntimeUploadUrlResponse(
            upload_url=upload_url,
            s3_key=s3_key,
            expires_in=600,
        )

    async def complete_upload(
        self,
        authenticated_cluster_id: str,
        s3_key: str,
        snapshot_at: datetime,
        fact_count: int | None,
    ) -> RuntimeCompleteResponse:
        self._validate_runtime_s3_key(authenticated_cluster_id, s3_key)

        if not self._s3.verify_file_exists(s3_key):
            raise HTTPException(status_code=400, detail="Runtime snapshot object not found in S3")

        uploaded_at = datetime.now(timezone.utc)
        snapshot = await self._repo.create(
            cluster_id=authenticated_cluster_id,
            s3_key=s3_key,
            snapshot_at=snapshot_at,
            uploaded_at=uploaded_at,
            fact_count=fact_count,
        )
        return RuntimeCompleteResponse(
            upload_id=snapshot.id,
            cluster_id=snapshot.cluster_id,
            s3_key=snapshot.s3_key,
            snapshot_at=snapshot.snapshot_at,
            uploaded_at=snapshot.uploaded_at,
            fact_count=snapshot.fact_count,
        )

    async def get_status(self, cluster_id: str, user_id: str) -> RuntimeStatusResponse:
        cluster = await self._clusters.get_by_id(cluster_id, user_id=user_id)
        if cluster is None:
            raise HTTPException(status_code=404, detail="Cluster not found")

        latest = await self._repo.get_latest_by_cluster_id(cluster_id)
        if latest is None:
            return RuntimeStatusResponse(
                cluster_id=cluster_id,
                last_uploaded_at=None,
                snapshot_at=None,
                fact_count=None,
                is_stale=True,
            )

        now = datetime.now(timezone.utc)
        stale_after = now - timedelta(seconds=settings.RUNTIME_STALE_THRESHOLD_SECONDS)
        uploaded_at = self._ensure_utc(latest.uploaded_at)
        return RuntimeStatusResponse(
            cluster_id=cluster_id,
            last_uploaded_at=uploaded_at,
            snapshot_at=self._ensure_utc(latest.snapshot_at),
            fact_count=latest.fact_count,
            is_stale=uploaded_at <= stale_after,
        )

    async def get_activities(
        self,
        cluster_id: str,
        user_id: str,
        limit: int = 50,
        snapshot_limit: int = 1,
    ) -> RuntimeActivityListResponse:
        cluster = await self._clusters.get_by_id(cluster_id, user_id=user_id)
        if cluster is None:
            raise HTTPException(status_code=404, detail="Cluster not found")

        snapshots = await self._repo.list_recent_by_cluster_id(cluster_id, limit=snapshot_limit)
        if not snapshots:
            return RuntimeActivityListResponse(cluster_id=cluster_id, snapshot_count=0, items=[])

        items: list[RuntimeActivityItemResponse] = []
        for snapshot in snapshots:
            payload = await asyncio.to_thread(self._s3.load_json, snapshot.s3_key)
            for fact in self._extract_facts(payload):
                item = self._build_activity_item(snapshot_at=snapshot.snapshot_at, fact=fact)
                if item is not None:
                    items.append(item)

        items.sort(key=lambda item: (item.observed_at, item.snapshot_at), reverse=True)
        return RuntimeActivityListResponse(
            cluster_id=cluster_id,
            snapshot_count=len(snapshots),
            items=items[:limit],
        )

    @staticmethod
    def _validate_runtime_s3_key(cluster_id: str, s3_key: str) -> None:
        match = _RUNTIME_KEY_PATTERN.fullmatch(s3_key)
        if match is None or match.group("cluster_id") != cluster_id:
            raise HTTPException(status_code=400, detail="s3_key does not belong to the authenticated cluster")

    @staticmethod
    def _ensure_utc(value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @staticmethod
    def _extract_facts(payload: Any) -> list[dict[str, Any]]:
        if not isinstance(payload, dict):
            return []
        facts = payload.get("facts")
        if not isinstance(facts, list):
            return []
        return [fact for fact in facts if isinstance(fact, dict)]

    def _build_activity_item(
        self,
        snapshot_at: datetime,
        fact: dict[str, Any],
    ) -> RuntimeActivityItemResponse | None:
        fact_type = self._as_str(fact.get("fact_type"))
        if not fact_type:
            return None

        actor = self._as_dict(fact.get("actor"))
        target = self._normalize_target(fact.get("target"))
        attributes = self._as_dict(fact.get("attributes"))
        observed_at = self._parse_datetime(fact.get("observed_at")) or self._ensure_utc(snapshot_at)
        fact_family = self._as_str(fact.get("fact_family"))
        action = self._as_str(fact.get("action"))
        severity = (
            self._as_str(fact.get("severity_hint"))
            or self._as_str(attributes.get("severity_hint"))
            or self._as_str(attributes.get("severity"))
        )
        success = self._as_bool(fact.get("success"))
        response_code = self._as_int(fact.get("response_code"))
        if response_code is None:
            response_code = self._as_int(attributes.get("response_code"))

        title = self._TITLE_BY_FACT_TYPE.get(fact_type, self._default_title(fact_type))
        summary = self._build_summary(
            fact_type=fact_type,
            action=action,
            actor=actor,
            target=target,
        )

        return RuntimeActivityItemResponse(
            snapshot_at=self._ensure_utc(snapshot_at),
            observed_at=observed_at,
            source=self._as_str(fact.get("source")),
            fact_type=fact_type,
            fact_family=fact_family,
            category=self._as_str(fact.get("category")),
            action=action,
            title=title,
            summary=summary,
            severity=severity,
            notable=self._is_notable(fact_family=fact_family, severity=severity, action=action),
            namespace=self._pick_first_str(actor, "namespace"),
            pod_name=self._pick_first_str(actor, "pod_name", "pod"),
            service_account=self._pick_first_str(actor, "service_account"),
            workload_name=self._pick_first_str(actor, "workload_name", "workload"),
            target=self._pick_first_str(target, "display", "name", "target", "resource_name", "path", "address", "host", "id", "value"),
            target_type=self._pick_first_str(target, "type", "target_type"),
            target_resource=self._pick_first_str(target, "resource", "resource_name", "kind"),
            target_namespace=self._pick_first_str(target, "namespace", "target_namespace"),
            success=success,
            response_code=response_code,
            scenario_tags=self._normalize_string_list(fact.get("scenario_tags")),
        )

    def _build_summary(
        self,
        *,
        fact_type: str,
        action: str | None,
        actor: dict[str, Any],
        target: dict[str, Any],
    ) -> str:
        namespace = self._pick_first_str(actor, "namespace")
        actor_name = self._pick_first_str(actor, "pod_name", "workload_name", "service_account")
        target_name = self._pick_first_str(target, "name", "display", "target", "resource_name", "path", "address", "host", "id", "value")
        target_namespace = self._pick_first_str(target, "namespace", "target_namespace")
        target_resource = self._pick_first_str(target, "resource", "resource_name", "kind")

        if fact_type == "secret_read":
            secret_name = target_name or "unknown secret"
            if target_namespace or namespace:
                return f"Secret {secret_name} was accessed in namespace {target_namespace or namespace}"
            return f"Secret {secret_name} was accessed"
        if fact_type == "sa_token_access":
            if actor_name and namespace:
                return f"Service account token access was observed from {actor_name} in namespace {namespace}"
            return "Service account token access was observed"
        if fact_type == "host_sensitive_path_access":
            return f"Sensitive host path {target_name or 'unknown path'} was accessed"
        if fact_type == "imds_access":
            if actor_name:
                return f"Instance metadata service was accessed by {actor_name}"
            return "Instance metadata service was accessed"
        if fact_type == "pod_exec":
            if actor_name and namespace:
                return f"Pod exec was observed against {actor_name} in namespace {namespace}"
            return "Pod exec was observed"
        if fact_type == "rolebinding_create":
            binding_name = target_name or "unknown rolebinding"
            if target_namespace or namespace:
                return f"RoleBinding {binding_name} was created in namespace {target_namespace or namespace}"
            return f"RoleBinding {binding_name} was created"
        if fact_type == "network_connect":
            return f"Network connection to {target_name or 'unknown destination'} was observed"
        if fact_type == "suspicious_process":
            return f"Suspicious process {target_name or 'unknown process'} was executed"

        fragments = [self._TITLE_BY_FACT_TYPE.get(fact_type, self._default_title(fact_type))]
        if action:
            fragments.append(f"action={action}")
        if target_resource or target_name:
            fragments.append(f"target={target_name or target_resource}")
        if namespace:
            fragments.append(f"namespace={namespace}")
        return "; ".join(fragments)

    @staticmethod
    def _default_title(fact_type: str) -> str:
        normalized = fact_type.replace("_", " ").strip()
        if not normalized:
            return "Runtime activity detected"
        return f"{normalized.capitalize()} detected"

    @staticmethod
    def _normalize_target(value: Any) -> dict[str, Any]:
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            return {"display": value}
        return {}

    @staticmethod
    def _as_dict(value: Any) -> dict[str, Any]:
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _as_str(value: Any) -> str | None:
        if isinstance(value, str):
            normalized = value.strip()
            return normalized or None
        return None

    @staticmethod
    def _as_bool(value: Any) -> bool | None:
        if isinstance(value, bool):
            return value
        return None

    @staticmethod
    def _as_int(value: Any) -> int | None:
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            normalized = value.strip()
            if normalized.isdigit():
                return int(normalized)
        return None

    @staticmethod
    def _pick_first_str(payload: dict[str, Any], *keys: str) -> str | None:
        for key in keys:
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None

    @classmethod
    def _normalize_string_list(cls, value: Any) -> list[str]:
        if not isinstance(value, list):
            return []
        items: list[str] = []
        for item in value:
            normalized = cls._as_str(item)
            if normalized is not None:
                items.append(normalized)
        return items

    @classmethod
    def _parse_datetime(cls, value: Any) -> datetime | None:
        normalized = cls._as_str(value)
        if normalized is None:
            return None
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError:
            return None
        return cls._ensure_utc(parsed)

    @staticmethod
    def _is_notable(
        *,
        fact_family: str | None,
        severity: str | None,
        action: str | None,
    ) -> bool:
        if fact_family == "credential_access":
            return True
        if severity in {"high", "critical"}:
            return True
        if action in {"list", "watch"}:
            return False
        return False
