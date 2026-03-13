import pytest
from uuid import uuid4

def test_create_cluster(client):
    response = client.post(
        "/api/clusters",
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

def test_create_cluster_invalid_type(client):
    response = client.post(
        "/api/clusters",
        json={
            "name": "invalid-cluster",
            "cluster_type": "invalid"
        }
    )
    assert response.status_code == 422

def test_list_clusters(client):
    client.post("/api/clusters", json={"name": "c1", "cluster_type": "eks"})
    client.post("/api/clusters", json={"name": "c2", "cluster_type": "self-managed"})
    
    response = client.get("/api/clusters")
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 2

def test_get_cluster(client):
    create_resp = client.post("/api/clusters", json={"name": "get-me", "cluster_type": "eks"})
    cluster_id = create_resp.json()["id"]
    
    response = client.get(f"/api/clusters/{cluster_id}")
    assert response.status_code == 200
    assert response.json()["name"] == "get-me"

def test_update_cluster(client):
    create_resp = client.post("/api/clusters", json={"name": "update-me", "cluster_type": "eks"})
    cluster_id = create_resp.json()["id"]
    
    response = client.patch(
        f"/api/clusters/{cluster_id}",
        json={"description": "updated description", "cluster_type": "self-managed"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["description"] == "updated description"
    assert data["cluster_type"] == "self-managed"

def test_delete_cluster(client):
    create_resp = client.post("/api/clusters", json={"name": "delete-me", "cluster_type": "eks"})
    cluster_id = create_resp.json()["id"]
    
    del_resp = client.delete(f"/api/clusters/{cluster_id}")
    assert del_resp.status_code == 204
    
    get_resp = client.get(f"/api/clusters/{cluster_id}")
    assert get_resp.status_code == 404
