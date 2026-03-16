import pytest
from uuid import uuid4
from fastapi.testclient import TestClient

from app.main import app

def test_create_cluster(client):
    response = client.post(
        "/api/v1/clusters",
        json={
            "name": "test-cluster",
            "cluster_type": "eks",
            "description": "A test cluster"
        }
    )
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "test-cluster"
    assert data["cluster_type"] == "eks"
    assert "id" in data
    assert "api_token" in data
    assert data["api_token"]

def test_create_cluster_invalid_type(client):
    response = client.post(
        "/api/v1/clusters",
        json={
            "name": "invalid-cluster",
            "cluster_type": "invalid"
        }
    )
    assert response.status_code == 422

def test_list_clusters(client):
    client.post("/api/v1/clusters", json={"name": "c1", "cluster_type": "eks"})
    client.post("/api/v1/clusters", json={"name": "c2", "cluster_type": "self-managed"})
    
    response = client.get("/api/v1/clusters")
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 2
    assert all("api_token" not in c for c in data)

def test_get_cluster(client):
    create_resp = client.post("/api/v1/clusters", json={"name": "get-me", "cluster_type": "eks"})
    cluster_id = create_resp.json()["id"]
    
    response = client.get(f"/api/v1/clusters/{cluster_id}")
    assert response.status_code == 200
    assert response.json()["name"] == "get-me"
    assert "api_token" not in response.json()

def test_update_cluster(client):
    create_resp = client.post("/api/v1/clusters", json={"name": "update-me", "cluster_type": "eks"})
    cluster_id = create_resp.json()["id"]
    
    response = client.patch(
        f"/api/v1/clusters/{cluster_id}",
        json={"description": "updated description", "cluster_type": "self-managed"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["description"] == "updated description"
    assert data["cluster_type"] == "self-managed"

def test_delete_cluster(client):
    create_resp = client.post("/api/v1/clusters", json={"name": "delete-me", "cluster_type": "eks"})
    cluster_id = create_resp.json()["id"]
    
    del_resp = client.delete(f"/api/v1/clusters/{cluster_id}")
    assert del_resp.status_code == 204
    
    get_resp = client.get(f"/api/v1/clusters/{cluster_id}")
    assert get_resp.status_code == 404


def test_create_cluster_token_is_persisted_for_auth_lookup():
    app.dependency_overrides.clear()
    name = f"persist-{uuid4().hex[:8]}"
    with TestClient(app) as client:
        create_resp = client.post(
            "/api/v1/clusters",
            json={"name": name, "cluster_type": "eks"},
        )
        assert create_resp.status_code == 201
        token = create_resp.json()["api_token"]

        pending_resp = client.get(
            "/api/v1/scans/pending",
            params={"scanner_type": "k8s"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert pending_resp.status_code == 204
