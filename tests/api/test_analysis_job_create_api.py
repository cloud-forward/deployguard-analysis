from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from app.application.di import get_analysis_service
from app.main import app


@pytest.fixture
def analysis_service():
    service = AsyncMock()
    service.create_analysis_job.return_value = {
        "job_id": "job-123",
        "status": "accepted",
        "message": "Analysis job created",
    }
    return service


@pytest.fixture
def client(analysis_service):
    app.dependency_overrides[get_analysis_service] = lambda: analysis_service
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


class TestAnalysisJobCreateApi:
    def test_create_analysis_job_without_cluster_id(self, client, analysis_service):
        response = client.post(
            "/api/v1/analysis/jobs",
            json={"k8s_scan_id": "k8s-1", "image_scan_id": "img-1"},
        )

        assert response.status_code == 202
        analysis_service.create_analysis_job.assert_awaited_once_with(
            k8s_scan_id="k8s-1",
            aws_scan_id=None,
            image_scan_id="img-1",
        )
