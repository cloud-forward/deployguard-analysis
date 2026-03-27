"""
S3 service for generating presigned URLs and verifying file existence.
"""
import json
import logging
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

from app.core.constants import (
    VALID_SCANNER_TYPES,
    S3_SCAN_PREFIX,
    canonical_scan_file_name,
    AWS_DEFAULT_REGION,
)

logger = logging.getLogger(__name__)


def format_runtime_upload_timestamp(timestamp: datetime) -> str:
    normalized = timestamp.astimezone(timezone.utc)
    return normalized.strftime("%Y%m%dT%H%M%SZ")


class S3Service:
    def __init__(self, bucket_name: str, region: str = AWS_DEFAULT_REGION):
        """
        Initialize S3 client using boto3.
        Get credentials from environment (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
        or from instance profile (if running on EC2).
        """
        self.bucket_name = bucket_name
        self.region = region
        self.client = boto3.client("s3", region_name=region)

    def generate_presigned_upload_url(
        self,
        cluster_id: str,
        scan_id: str,
        scanner_type: str,
        file_name: str,
        expires_in: int = 600,
    ) -> tuple[str, str]:
        """
        Generate a presigned PUT URL for S3 upload.

        S3 bucket layout:
        dg-raw-scans
         └ scans
            └ cluster_id
               └ scan_id
                  ├ k8s
                  ├ aws
                  ├ image
                  └ image

        S3 key format: scans/{cluster_id}/{scan_id}/{scanner_type}/{scanner_type}-snapshot.json

        scanner_type must be one of: "k8s", "aws", "image".

        Returns: (presigned_url, s3_key)
        """
        if scanner_type not in VALID_SCANNER_TYPES:
            raise ValueError(
                f"Invalid scanner_type '{scanner_type}'. Must be one of: {sorted(VALID_SCANNER_TYPES)}"
            )
        canonical_file_name = canonical_scan_file_name(scanner_type)
        s3_key = f"{S3_SCAN_PREFIX}/{cluster_id}/{scan_id}/{scanner_type}/{canonical_file_name}"
        try:
            presigned_url = self.client.generate_presigned_url(
                "put_object",
                Params={"Bucket": self.bucket_name, "Key": s3_key},
                ExpiresIn=expires_in,
            )
        except ClientError as e:
            logger.error("Failed to generate presigned URL for key '%s': %s", s3_key, e)
            raise
        return presigned_url, s3_key

    def generate_runtime_presigned_upload_url(
        self,
        cluster_id: str,
        uploaded_at: datetime,
        expires_in: int = 600,
    ) -> tuple[str, str]:
        timestamp = format_runtime_upload_timestamp(uploaded_at)
        s3_key = f"runtime/{cluster_id}/{timestamp}/events.json"
        try:
            presigned_url = self.client.generate_presigned_url(
                "put_object",
                Params={"Bucket": self.bucket_name, "Key": s3_key},
                ExpiresIn=expires_in,
            )
        except ClientError as e:
            logger.error("Failed to generate runtime presigned URL for key '%s': %s", s3_key, e)
            raise
        return presigned_url, s3_key

    def generate_presigned_download_url(
        self,
        s3_key: str,
        expires_in: int = 600,
    ) -> str:
        """
        Generate a presigned GET URL for S3 download.

        Returns: presigned_url
        """
        try:
            presigned_url = self.client.generate_presigned_url(
                "get_object",
                Params={"Bucket": self.bucket_name, "Key": s3_key},
                ExpiresIn=expires_in,
            )
        except ClientError as e:
            logger.error("Failed to generate download presigned URL for key '%s': %s", s3_key, e)
            raise
        return presigned_url

    def verify_file_exists(self, s3_key: str) -> bool:
        """
        Check if a file exists in S3 (used during scan complete to verify uploads).
        Uses head_object. Returns True if exists, False if not.
        """
        try:
            self.client.head_object(Bucket=self.bucket_name, Key=s3_key)
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "404":
                return False
            logger.error("Error checking existence of key '%s': %s", s3_key, e)
            raise

    def load_json(self, s3_key: str) -> dict[str, Any]:
        """
        Load and decode a JSON object stored in S3.
        """
        try:
            response = self.client.get_object(Bucket=self.bucket_name, Key=s3_key)
        except ClientError as e:
            logger.error("Failed to load JSON object for key '%s': %s", s3_key, e)
            raise

        body = response["Body"].read()
        if isinstance(body, bytes):
            body = body.decode("utf-8")
        return json.loads(body)
