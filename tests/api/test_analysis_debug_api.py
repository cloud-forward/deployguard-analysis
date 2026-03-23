from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.application.di import get_analysis_service
from app.main import app


@pytest.fixture
def analysis_service():
    service = AsyncMock()
    service.execute_analysis_debug.return_value = {"ok": True}
    return service


@pytest.fixture
def client(analysis_service):
    app.dependency_overrides[get_analysis_service] = lambda: analysis_service
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


class TestAnalysisDebugApi:
    def test_debug_execute_without_cluster_id(self, client, analysis_service):
        response = client.post(
            "/api/v1/analysis/execute",
            json={"k8s_scan_id": "k8s-1", "image_scan_id": "img-1"},
        )

        assert response.status_code == 200
        analysis_service.execute_analysis_debug.assert_awaited_once_with(
            k8s_scan_id="k8s-1",
            aws_scan_id=None,
            image_scan_id="img-1",
        )

    def test_debug_execute_supports_aws_only_request(self, client, analysis_service):
        response = client.post(
            "/api/v1/analysis/execute",
            json={"aws_scan_id": "aws-1"},
        )

        assert response.status_code == 200
        analysis_service.execute_analysis_debug.assert_awaited_once_with(
            k8s_scan_id=None,
            aws_scan_id="aws-1",
            image_scan_id=None,
        )

    def test_debug_execute_requires_at_least_one_scan_id(self, client, analysis_service):
        response = client.post("/api/v1/analysis/execute", json={})

        assert response.status_code == 422
        analysis_service.execute_analysis_debug.assert_not_called()

    def test_debug_execute_surfaces_validation_error_from_service(self, client, analysis_service):
        analysis_service.execute_analysis_debug.side_effect = HTTPException(
            status_code=400,
            detail="Scan aws-1 has scanner_type=aws, expected k8s",
        )

        response = client.post("/api/v1/analysis/execute", json={"k8s_scan_id": "aws-1"})

        assert response.status_code == 400
        assert response.json()["detail"] == "Scan aws-1 has scanner_type=aws, expected k8s"
