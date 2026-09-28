import pytest

pytestmark = pytest.mark.integration


def test_health_reports_version_and_env(client):
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json() == {
        "status": "healthy",
        "version": "9.9.9",
        "environment": "test",
        "database": "ok",
    }


def test_health_returns_503_when_db_is_down(client, monkeypatch):
    monkeypatch.setattr(client.app.state.db, "ping", lambda: False)
    res = client.get("/health")
    assert res.status_code == 503
    assert res.json()["status"] == "unhealthy"


def test_metrics_endpoint_is_prometheus_format(client):
    client.get("/health")
    body = client.get("/metrics").text
    assert 'secureflow_app_info{env="test",version="9.9.9"} 1.0' in body
    assert "secureflow_http_requests_total" in body
    assert 'secureflow_incidents_open{severity="CRITICAL"} 0.0' in body


def test_attack_counters_start_at_zero(client):
    # without these the first attack wave after a deploy never trips AttackWave
    body = client.get("/metrics").text
    for attack_type in ("sql_injection", "xss", "command_injection", "brute_force"):
        assert f'secureflow_attacks_detected_total{{attack_type="{attack_type}"}} 0.0' in body


def test_dashboard_is_served(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "SecureFlow" in res.text
    assert client.get("/static/app.js").status_code == 200


def test_swagger_docs_available(client):
    assert client.get("/docs").status_code == 200
