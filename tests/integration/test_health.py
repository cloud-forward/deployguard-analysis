"""
Tests for the health endpoint.
"""
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health_endpoint():
    """
    Test that the /health endpoint returns 200 and correct status.
    """
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "db" in data

def test_root_endpoint():
    """
    Test that the root endpoint returns 200.
    """
    response = client.get("/")
    assert response.status_code == 200
    assert "service" in response.json()
