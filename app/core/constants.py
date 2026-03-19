"""
Central constant definitions for the DeployGuard architecture.

All magic strings related to scanner types, scan statuses, S3 structure,
and API prefixes must be imported from here — never hardcoded in business logic.
"""

# ---------------------------------------------------------------------------
# S3
# ---------------------------------------------------------------------------

S3_BUCKET_NAME: str = "dg-raw-scans"

# S3 path templates
# scans/{cluster_id}/{scan_id}/{scanner_type}/scan.json
S3_SCAN_PREFIX: str = "scans"
S3_SCAN_FILE_NAME: str = "scan.json"

# runtime/{cluster_id}/{date}/events.json
S3_RUNTIME_PREFIX: str = "runtime"
S3_RUNTIME_FILE_NAME: str = "events.json"

# ---------------------------------------------------------------------------
# Scanner types
# ---------------------------------------------------------------------------

SCANNER_TYPE_K8S: str = "k8s"
SCANNER_TYPE_AWS: str = "aws"
SCANNER_TYPE_IMAGE: str = "image"
SCANNER_TYPE_RUNTIME: str = "runtime"

VALID_SCANNER_TYPES: frozenset[str] = frozenset({
    SCANNER_TYPE_K8S,
    SCANNER_TYPE_AWS,
    SCANNER_TYPE_IMAGE,
    SCANNER_TYPE_RUNTIME,
})

# ---------------------------------------------------------------------------
# Scan statuses
# ---------------------------------------------------------------------------

SCAN_STATUS_QUEUED: str = "queued"
SCAN_STATUS_RUNNING: str = "running"
SCAN_STATUS_UPLOADING: str = "uploading"
SCAN_STATUS_PROCESSING: str = "processing"
SCAN_STATUS_COMPLETED: str = "completed"
SCAN_STATUS_FAILED: str = "failed"

VALID_SCAN_STATUSES: frozenset[str] = frozenset({
    SCAN_STATUS_QUEUED,
    SCAN_STATUS_RUNNING,
    SCAN_STATUS_UPLOADING,
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_FAILED,
})

# Statuses that indicate a scan session is still active (not terminal)
ACTIVE_SCAN_STATUSES: tuple[str, ...] = (
    SCAN_STATUS_QUEUED,
    SCAN_STATUS_RUNNING,
    SCAN_STATUS_UPLOADING,
)

# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

API_PREFIX_SCANS: str = "/api/scans"

# ---------------------------------------------------------------------------
# AWS / region
# ---------------------------------------------------------------------------

AWS_DEFAULT_REGION: str = "ap-northeast-2"
