from __future__ import annotations

from datetime import datetime, UTC
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.application.di import get_analysis_service
from app.main import app


@pytest.fixture
def analysis_service():
    service = AsyncMock()
    service.list_analysis_jobs.return_value = {
        "items": [
            {
                "job_id": "job-123",
                "status": "running",
                "current_step": "graph_building",
                "k8s_scan_id": "k8s-1",
                "aws_scan_id": None,
                "image_scan_id": "img-1",
                "expected_scans": ["k8s", "image"],
                "error_message": None,
                "created_at": datetime(2026, 3, 23, 0, 0, tzinfo=UTC),
                "started_at": datetime(2026, 3, 23, 0, 1, tzinfo=UTC),
                "completed_at": None,
                "graph_id": None,
            }
        ],
        "total": 1,
    }
    service.get_analysis_job.return_value = {
        "job_id": "job-123",
        "cluster_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "status": "running",
        "current_step": "graph_building",
        "k8s_scan_id": "k8s-1",
        "aws_scan_id": None,
        "image_scan_id": "img-1",
        "expected_scans": ["k8s", "image"],
        "error_message": None,
        "created_at": datetime(2026, 3, 23, 0, 0, tzinfo=UTC),
        "started_at": datetime(2026, 3, 23, 0, 1, tzinfo=UTC),
        "completed_at": None,
        "graph_id": None,
    }
    service.get_analysis_result.return_value = {
        "job": service.get_analysis_job.return_value,
        "summary": {
            "graph_id": None,
            "generated_at": None,
            "graph_status": None,
            "node_count": 0,
            "edge_count": 0,
            "entry_point_count": 0,
            "crown_jewel_count": 0,
            "attack_path_count": 0,
            "remediation_recommendation_count": 0,
        },
        "attack_paths_preview": [],
        "remediation_preview": [],
        "links": {
            "analysis_job": "/api/v1/analysis/jobs/job-123",
            "attack_graph": "/api/v1/clusters/a1b2c3d4-e5f6-7890-abcd-ef1234567890/attack-graph",
            "attack_paths": "/api/v1/clusters/a1b2c3d4-e5f6-7890-abcd-ef1234567890/attack-paths",
            "remediation_recommendations": "/api/v1/clusters/a1b2c3d4-e5f6-7890-abcd-ef1234567890/remediation-recommendations",
            "link_scope": "cluster_latest_view",
        },
    }
    return service


@pytest.fixture
def client(analysis_service):
    app.dependency_overrides[get_analysis_service] = lambda: analysis_service
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


class TestAnalysisReadApi:
    def test_list_analysis_jobs_by_cluster(self, client, analysis_service):
        response = client.get("/api/v1/clusters/a1b2c3d4-e5f6-7890-abcd-ef1234567890/analysis/jobs")

        assert response.status_code == 200
        assert response.json()["total"] == 1
        assert response.json()["items"][0]["job_id"] == "job-123"
        analysis_service.list_analysis_jobs.assert_awaited_once_with(
            cluster_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            status=None,
        )

    def test_list_analysis_jobs_by_cluster_with_status_filter(self, client, analysis_service):
        response = client.get(
            "/api/v1/clusters/a1b2c3d4-e5f6-7890-abcd-ef1234567890/analysis/jobs",
            params={"status": "running"},
        )

        assert response.status_code == 200
        analysis_service.list_analysis_jobs.assert_awaited_with(
            cluster_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            status="running",
        )

    def test_get_analysis_job_by_id(self, client, analysis_service):
        response = client.get("/api/v1/analysis/jobs/job-123")

        assert response.status_code == 200
        assert response.json()["job_id"] == "job-123"
        assert response.json()["cluster_id"] == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        analysis_service.get_analysis_job.assert_awaited_once_with("job-123")

    def test_get_analysis_job_missing_returns_404(self, client, analysis_service):
        analysis_service.get_analysis_job.side_effect = HTTPException(status_code=404, detail="Analysis job not found: missing-job")

        response = client.get("/api/v1/analysis/jobs/missing-job")

        assert response.status_code == 404
        assert response.json()["detail"] == "Analysis job not found: missing-job"

    def test_get_analysis_result_by_id(self, client, analysis_service):
        response = client.get("/api/v1/analysis/job-123/result")

        assert response.status_code == 200
        body = response.json()
        assert body["job"]["job_id"] == "job-123"
        assert body["summary"]["graph_id"] is None
        assert body["attack_paths_preview"] == []
        assert body["remediation_preview"] == []
        assert body["links"]["link_scope"] == "cluster_latest_view"
        analysis_service.get_analysis_result.assert_awaited_once_with("job-123")

    def test_get_analysis_result_does_not_call_execution_methods(self, client, analysis_service):
        response = client.get("/api/v1/analysis/job-123/result")

        assert response.status_code == 200
        analysis_service.get_analysis_result.assert_awaited_once_with("job-123")
        analysis_service.execute_analysis_job.assert_not_called()
        analysis_service.execute_analysis.assert_not_called()
