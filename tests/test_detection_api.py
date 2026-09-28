"""End-to-end checks that attacks against the API are blocked and turned
into incidents automatically."""

import pytest

from tests.conftest import ANALYST

pytestmark = pytest.mark.integration


def auto_incidents(client):
    return [i for i in client.get("/incidents", headers=ANALYST).json() if i["detected_by"] == "auto"]


def test_sql_injection_is_blocked_and_recorded(client):
    res = client.get("/incidents", params={"source": "' OR 1=1--"}, headers=ANALYST)
    assert res.status_code == 403
    assert res.json()["attack_type"] == "sql_injection"

    [incident] = auto_incidents(client)
    assert incident["title"] == "SQL Injection Attempt"
    assert incident["severity"] == "HIGH"
    assert incident["source"] == "SecureFlow Detector"
    assert incident["attacker_ip"] == "testclient"


def test_attacks_are_blocked_even_without_a_key(client):
    # detection runs before auth, so anonymous attackers are caught too
    assert client.get("/.env").status_code == 403
    assert auto_incidents(client)[0]["title"] == "Reconnaissance Probe"


def test_repeat_attacks_do_not_flood_incidents(client):
    for _ in range(10):
        client.get("/incidents", params={"q": "<script>alert(1)</script>"})
    assert len(auto_incidents(client)) == 1

    # ...but every attempt is still counted in the metrics
    body = client.get("/metrics").text
    assert 'secureflow_attacks_detected_total{attack_type="xss"} 10.0' in body


def test_brute_force_creates_incident(client):
    for _ in range(5):
        assert client.get("/incidents", headers={"X-API-Key": "guess"}).status_code == 401

    [incident] = auto_incidents(client)
    assert incident["title"] == "Brute-Force Attack on API Keys"
    assert "5 invalid API keys" in incident["description"]


def test_four_bad_keys_is_not_brute_force(client):
    for _ in range(4):
        client.get("/incidents", headers={"X-API-Key": "typo"})
    assert auto_incidents(client) == []


def test_scanner_user_agent_is_blocked(client):
    res = client.get("/incidents", headers={**ANALYST, "User-Agent": "sqlmap/1.7"})
    assert res.status_code == 403


def test_payloads_inside_incident_body_are_allowed(client):
    # analysts paste real payloads into descriptions - that must not be blocked
    res = client.post(
        "/incidents",
        json={
            "title": "SQLi seen in WAF logs",
            "severity": "HIGH",
            "source": "WAF",
            "description": "Payload was: ' OR 1=1-- and <script>alert(1)</script>",
        },
        headers=ANALYST,
    )
    assert res.status_code == 201
    assert auto_incidents(client) == []


def test_health_and_metrics_are_never_blocked(client):
    assert client.get("/health", headers={"User-Agent": "nikto"}).status_code == 200
    assert client.get("/metrics", headers={"User-Agent": "nikto"}).status_code == 200
