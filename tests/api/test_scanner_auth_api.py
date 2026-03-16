from fastapi.testclient import TestClient

from app.main import app


def _pending_request(client: TestClient, headers: dict | None = None):
    return client.get(
        "/api/v1/scans/pending",
        params={
            "scanner_type": "k8s",
            "claimed_by": "worker-1",
        },
        headers=headers or {},
    )


def test_pending_requires_authorization_header():
    app.dependency_overrides.clear()
    with TestClient(app) as client:
        response = _pending_request(client)
    assert response.status_code == 401


def test_pending_rejects_malformed_authorization_header():
    app.dependency_overrides.clear()
    with TestClient(app) as client:
        response = _pending_request(client, headers={"Authorization": "Token abc"})
    assert response.status_code == 401


def test_pending_rejects_invalid_api_token():
    app.dependency_overrides.clear()
    with TestClient(app) as client:
        response = _pending_request(client, headers={"Authorization": "Bearer invalid-token"})
    assert response.status_code == 403
