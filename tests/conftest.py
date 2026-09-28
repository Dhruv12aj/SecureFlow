import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

ANALYST = {"X-API-Key": "test-analyst-key"}
ADMIN = {"X-API-Key": "test-admin-key"}


@pytest.fixture
def settings(tmp_path):
    return Settings(
        app_env="test",
        app_version="9.9.9",
        database_path=str(tmp_path / "test.db"),
        analyst_api_key="test-analyst-key",
        admin_api_key="test-admin-key",
        brute_force_threshold=5,
        brute_force_window_seconds=60,
    )


@pytest.fixture
def client(settings):
    # fresh app + empty database for every test
    with TestClient(create_app(settings)) as c:
        yield c


@pytest.fixture
def sample_incident():
    return {
        "title": "SQL Injection Attempt",
        "severity": "HIGH",
        "status": "OPEN",
        "source": "Web Application",
        "description": "Multiple suspicious SQL queries detected",
    }
