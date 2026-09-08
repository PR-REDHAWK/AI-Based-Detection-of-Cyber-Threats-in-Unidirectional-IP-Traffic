import pytest
import asyncio
from fastapi.testclient import TestClient
from backend.main import app
from backend.database import init_db

@pytest.fixture(autouse=True)
def setup_database():
    asyncio.run(init_db())

def test_health_endpoint():
    with TestClient(app) as client:
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "HEALTHY"
        assert data["mode"] == "READ_ONLY_UNIDIRECTIONAL"
        assert data["active_response"] is False

def test_alerts_endpoint():
    with TestClient(app) as client:
        response = client.get("/api/alerts")
        assert response.status_code == 200
        assert isinstance(response.json(), list)

def test_statistics_endpoint():
    with TestClient(app) as client:
        response = client.get("/api/statistics")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "MONITORING"
        assert "severity_counts" in data

def test_models_endpoint():
    with TestClient(app) as client:
        response = client.get("/api/models")
        assert response.status_code == 200
        models = response.json()
        assert len(models) >= 3
