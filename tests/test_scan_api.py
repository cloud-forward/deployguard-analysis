"""
Integration tests for scan API endpoints.
"""


class TestScanStartAPI:

    def test_start_scan_success(self, client):
        """POST /api/scans/start returns 201 with scan_id"""
        response = client.post("/api/scans/start", json={
            "cluster_id": "prod-01",
            "scanner_type": "k8s"
        })

        assert response.status_code == 201
        data = response.json()
        assert "scan_id" in data
        assert data["status"] == "created"

    def test_start_scan_invalid_scanner_type(self, client):
        """Invalid scanner_type returns 422"""
        response = client.post("/api/scans/start", json={
            "cluster_id": "prod-01",
            "scanner_type": "invalid"
        })

        assert response.status_code == 422

    def test_start_scan_missing_fields(self, client):
        """Missing required fields returns 422"""
        response = client.post("/api/scans/start", json={})
        assert response.status_code == 422


class TestUploadUrlAPI:

    def test_upload_url_success(self, client):
        """POST /api/scans/{id}/upload-url returns presigned URL"""
        start_resp = client.post("/api/scans/start", json={
            "cluster_id": "prod-01", "scanner_type": "k8s"
        })
        scan_id = start_resp.json()["scan_id"]

        response = client.post(f"/api/scans/{scan_id}/upload-url", json={
            "file_name": "k8s_scan.json"
        })

        assert response.status_code == 200
        data = response.json()
        assert "upload_url" in data
        assert "s3_key" in data
        assert data["expires_in"] == 600

    def test_upload_url_scan_not_found(self, client):
        """Unknown scan_id returns 404"""
        response = client.post("/api/scans/nonexistent/upload-url", json={
            "file_name": "k8s_scan.json"
        })
        assert response.status_code == 404

    def test_upload_url_non_json_file_rejected(self, client):
        """Non-JSON file name returns 422"""
        start_resp = client.post("/api/scans/start", json={
            "cluster_id": "c1", "scanner_type": "k8s"
        })
        scan_id = start_resp.json()["scan_id"]

        response = client.post(f"/api/scans/{scan_id}/upload-url", json={
            "file_name": "scan.txt"
        })
        assert response.status_code == 422


class TestCompleteAPI:

    def test_complete_scan_success(self, client):
        """POST /api/scans/{id}/complete returns 202"""
        start_resp = client.post("/api/scans/start", json={
            "cluster_id": "prod-01", "scanner_type": "k8s"
        })
        scan_id = start_resp.json()["scan_id"]

        response = client.post(f"/api/scans/{scan_id}/complete", json={
            "files": ["scans/prod-01/" + scan_id + "/k8s_scan.json"]
        })

        assert response.status_code == 202
        assert response.json()["status"] == "processing"

    def test_complete_scan_not_found(self, client):
        """Unknown scan_id returns 404"""
        response = client.post("/api/scans/nonexistent/complete", json={
            "files": ["some/file.json"]
        })
        assert response.status_code == 404

    def test_complete_scan_empty_files_rejected(self, client):
        """Empty files list returns 422"""
        start_resp = client.post("/api/scans/start", json={
            "cluster_id": "c1", "scanner_type": "k8s"
        })
        scan_id = start_resp.json()["scan_id"]

        response = client.post(f"/api/scans/{scan_id}/complete", json={
            "files": []
        })
        assert response.status_code == 422


class TestStatusAPI:

    def test_get_status_success(self, client):
        """GET /api/scans/{id}/status returns current state"""
        start_resp = client.post("/api/scans/start", json={
            "cluster_id": "prod-01", "scanner_type": "k8s"
        })
        scan_id = start_resp.json()["scan_id"]

        response = client.get(f"/api/scans/{scan_id}/status")

        assert response.status_code == 200
        data = response.json()
        assert data["scan_id"] == scan_id
        assert data["cluster_id"] == "prod-01"
        assert data["status"] == "created"

    def test_get_status_not_found(self, client):
        """Unknown scan_id returns 404"""
        response = client.get("/api/scans/nonexistent/status")
        assert response.status_code == 404


class TestScanFlow:

    def test_full_scan_flow(self, client):
        """Complete flow: start → upload-url → complete → status check"""

        # 1. Start scan
        start_resp = client.post("/api/scans/start", json={
            "cluster_id": "flow-test", "scanner_type": "k8s"
        })
        assert start_resp.status_code == 201
        scan_id = start_resp.json()["scan_id"]

        # 2. Get upload URL
        url_resp = client.post(f"/api/scans/{scan_id}/upload-url", json={
            "file_name": "k8s_scan.json"
        })
        assert url_resp.status_code == 200
        s3_key = url_resp.json()["s3_key"]

        # 3. Complete scan
        complete_resp = client.post(f"/api/scans/{scan_id}/complete", json={
            "files": [s3_key]
        })
        assert complete_resp.status_code == 202

        # 4. Check status
        status_resp = client.get(f"/api/scans/{scan_id}/status")
        assert status_resp.status_code == 200
        assert status_resp.json()["status"] == "processing"
