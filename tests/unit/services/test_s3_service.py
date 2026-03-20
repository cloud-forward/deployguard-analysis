from unittest.mock import patch, MagicMock
import pytest
from app.application.services.s3_service import S3Service


class TestS3Service:

    def setup_method(self):
        """Create S3Service with mocked boto3"""
        with patch("boto3.client") as mock_boto:
            self.mock_s3_client = MagicMock()
            mock_boto.return_value = self.mock_s3_client
            self.service = S3Service(
                bucket_name="test-bucket",
                region="ap-northeast-2"
            )

    def test_generate_presigned_url_returns_url_and_key(self):
        """Presigned URL generation returns both URL and S3 key"""
        self.mock_s3_client.generate_presigned_url.return_value = "https://test-bucket.s3.amazonaws.com/signed-url"

        url, key = self.service.generate_presigned_upload_url(
            cluster_id="prod-01",
            scan_id="scan-001",
            scanner_type="k8s",
            file_name="k8s_scan.json"
        )

        assert url == "https://test-bucket.s3.amazonaws.com/signed-url"
        assert key == "scans/prod-01/scan-001/k8s/k8s_scan.json"

    def test_s3_key_format(self):
        """S3 key follows format: scans/{cluster_id}/{scan_id}/{scanner_type}/{file_name}"""
        self.mock_s3_client.generate_presigned_url.return_value = "https://url"

        _, key = self.service.generate_presigned_upload_url(
            cluster_id="my-cluster",
            scan_id="abc-123",
            scanner_type="aws",
            file_name="aws_scan.json"
        )

        assert key == "scans/my-cluster/abc-123/aws/aws_scan.json"

    def test_presigned_url_called_with_correct_params(self):
        """boto3 called with PUT method and correct bucket/key"""
        self.mock_s3_client.generate_presigned_url.return_value = "https://url"

        self.service.generate_presigned_upload_url(
            cluster_id="c1", scan_id="s1", scanner_type="image", file_name="f1.json"
        )

        self.mock_s3_client.generate_presigned_url.assert_called_once_with(
            "put_object",
            Params={
                "Bucket": "test-bucket",
                "Key": "scans/c1/s1/image/f1.json"
            },
            ExpiresIn=600
        )

    def test_generate_presigned_download_url_returns_url(self):
        """Download presigned URL generation returns the signed URL"""
        self.mock_s3_client.generate_presigned_url.return_value = "https://test-bucket.s3.amazonaws.com/download-url"

        url = self.service.generate_presigned_download_url(
            "scans/prod-01/scan-001/k8s/k8s_scan.json"
        )

        assert url == "https://test-bucket.s3.amazonaws.com/download-url"

    def test_download_presigned_url_called_with_correct_params(self):
        """boto3 called with GET method and correct bucket/key"""
        self.mock_s3_client.generate_presigned_url.return_value = "https://url"

        self.service.generate_presigned_download_url(
            "scans/c1/s1/image/f1.json"
        )

        self.mock_s3_client.generate_presigned_url.assert_called_with(
            "get_object",
            Params={
                "Bucket": "test-bucket",
                "Key": "scans/c1/s1/image/f1.json"
            },
            ExpiresIn=600
        )

    def test_verify_file_exists_true(self):
        """verify_file_exists returns True when file exists"""
        self.mock_s3_client.head_object.return_value = {"ContentLength": 1024}

        result = self.service.verify_file_exists("scans/c1/s1/k8s/f1.json")
        assert result is True

    def test_verify_file_exists_false(self):
        """verify_file_exists returns False when file not found"""
        from botocore.exceptions import ClientError
        self.mock_s3_client.head_object.side_effect = ClientError(
            {"Error": {"Code": "404"}}, "HeadObject"
        )

        result = self.service.verify_file_exists("scans/c1/s1/k8s/missing.json")
        assert result is False

    def test_presigned_url_expiration_default(self):
        """Default expiration is 600 seconds"""
        self.mock_s3_client.generate_presigned_url.return_value = "https://url"

        self.service.generate_presigned_upload_url("c1", "s1", "k8s", "f.json")

        call_args = self.mock_s3_client.generate_presigned_url.call_args
        assert call_args[1]["ExpiresIn"] == 600

    def test_presigned_url_custom_expiration(self):
        """Custom expiration is passed through"""
        self.mock_s3_client.generate_presigned_url.return_value = "https://url"

        self.service.generate_presigned_upload_url("c1", "s1", "k8s", "f.json", expires_in=300)

        call_args = self.mock_s3_client.generate_presigned_url.call_args
        assert call_args[1]["ExpiresIn"] == 300

    def test_download_presigned_url_expiration_default(self):
        """Default download expiration is 600 seconds"""
        self.mock_s3_client.generate_presigned_url.return_value = "https://url"

        self.service.generate_presigned_download_url("scans/c1/s1/k8s/f.json")

        call_args = self.mock_s3_client.generate_presigned_url.call_args
        assert call_args[1]["ExpiresIn"] == 600

    def test_download_presigned_url_custom_expiration(self):
        """Custom download expiration is passed through"""
        self.mock_s3_client.generate_presigned_url.return_value = "https://url"

        self.service.generate_presigned_download_url("scans/c1/s1/k8s/f.json", expires_in=300)

        call_args = self.mock_s3_client.generate_presigned_url.call_args
        assert call_args[1]["ExpiresIn"] == 300

    @pytest.mark.parametrize("scanner_type", ["k8s", "aws", "image"])
    def test_valid_scanner_types_accepted(self, scanner_type):
        """All valid scanner types are accepted without error"""
        self.mock_s3_client.generate_presigned_url.return_value = "https://url"

        url, key = self.service.generate_presigned_upload_url(
            cluster_id="c1", scan_id="s1", scanner_type=scanner_type, file_name="f.json"
        )

        assert f"/{scanner_type}/" in key

    @pytest.mark.parametrize("scanner_type", ["unknown", "", "K8S", "AWS"])
    def test_invalid_scanner_type_raises_value_error(self, scanner_type):
        """Invalid scanner_type raises ValueError"""
        with pytest.raises(ValueError, match="Invalid scanner_type"):
            self.service.generate_presigned_upload_url(
                cluster_id="c1", scan_id="s1", scanner_type=scanner_type, file_name="f.json"
            )
