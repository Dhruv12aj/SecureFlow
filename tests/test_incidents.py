import pytest

from tests.conftest import ADMIN, ANALYST

pytestmark = pytest.mark.integration


def create(client, data, headers=ANALYST):
    res = client.post("/incidents", json=data, headers=headers)
    assert res.status_code == 201, res.text
    return res.json()


# --- create / read -------------------------------------------------------

def test_create_incident(client, sample_incident):
    incident = create(client, sample_incident)
    assert incident["id"] == 1
    assert incident["title"] == "SQL Injection Attempt"
    assert incident["detected_by"] == "analyst"
    assert incident["risk_score"] == 60
    assert incident["is_overdue"] is False


def test_get_incident_by_id(client, sample_incident):
    created = create(client, sample_incident)
    res = client.get(f"/incidents/{created['id']}", headers=ANALYST)
    assert res.status_code == 200
    assert res.json()["source"] == "Web Application"


def test_list_incidents_newest_first(client, sample_incident):
    create(client, sample_incident)
    create(client, {**sample_incident, "title": "Phishing email reported", "severity": "LOW"})
    titles = [i["title"] for i in client.get("/incidents", headers=ANALYST).json()]
    assert titles == ["Phishing email reported", "SQL Injection Attempt"]


def test_filter_by_severity_and_status(client, sample_incident):
    create(client, sample_incident)
    create(client, {**sample_incident, "severity": "CRITICAL"})
    create(client, {**sample_incident, "severity": "CRITICAL", "status": "RESOLVED"})

    res = client.get("/incidents?severity=CRITICAL&status=OPEN", headers=ANALYST)
    assert len(res.json()) == 1


def test_filter_by_source(client, sample_incident):
    create(client, sample_incident)
    create(client, {**sample_incident, "source": "Email Gateway"})
    res = client.get("/incidents?source=email", headers=ANALYST)
    assert [i["source"] for i in res.json()] == ["Email Gateway"]


def test_filter_overdue(client, sample_incident):
    create(client, sample_incident)
    assert client.get("/incidents?overdue=true", headers=ANALYST).json() == []
    assert len(client.get("/incidents?overdue=false", headers=ANALYST).json()) == 1


def test_missing_incident_returns_404(client):
    assert client.get("/incidents/999", headers=ANALYST).status_code == 404


# --- validation ----------------------------------------------------------

@pytest.mark.parametrize(
    "bad_field",
    [
        {"severity": "SUPER-HIGH"},
        {"status": "DONE"},
        {"title": "x"},
        {"source": ""},
    ],
)
def test_invalid_payloads_are_rejected(client, sample_incident, bad_field):
    res = client.post("/incidents", json={**sample_incident, **bad_field}, headers=ANALYST)
    assert res.status_code == 422


def test_missing_required_field(client):
    res = client.post("/incidents", json={"title": "No severity here"}, headers=ANALYST)
    assert res.status_code == 422


# --- update --------------------------------------------------------------

def test_update_status_only(client, sample_incident):
    created = create(client, sample_incident)
    res = client.put(f"/incidents/{created['id']}", json={"status": "INVESTIGATING"}, headers=ANALYST)
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "INVESTIGATING"
    assert body["title"] == sample_incident["title"]  # untouched


def test_resolving_sets_resolved_at_and_clears_risk(client, sample_incident):
    created = create(client, sample_incident)
    body = client.put(f"/incidents/{created['id']}", json={"status": "RESOLVED"}, headers=ANALYST).json()
    assert body["resolved_at"] is not None
    assert body["risk_score"] == 0

    reopened = client.put(f"/incidents/{created['id']}", json={"status": "OPEN"}, headers=ANALYST).json()
    assert reopened["resolved_at"] is None


def test_empty_update_changes_nothing(client, sample_incident):
    created = create(client, sample_incident)
    res = client.put(f"/incidents/{created['id']}", json={}, headers=ANALYST)
    assert res.status_code == 200
    assert res.json()["updated_at"] == created["updated_at"]


def test_update_missing_incident(client):
    assert client.put("/incidents/42", json={"status": "RESOLVED"}, headers=ANALYST).status_code == 404


# --- delete + roles ------------------------------------------------------

def test_admin_can_delete(client, sample_incident):
    created = create(client, sample_incident)
    assert client.delete(f"/incidents/{created['id']}", headers=ADMIN).status_code == 204
    assert client.get(f"/incidents/{created['id']}", headers=ADMIN).status_code == 404


def test_analyst_cannot_delete(client, sample_incident):
    created = create(client, sample_incident)
    assert client.delete(f"/incidents/{created['id']}", headers=ANALYST).status_code == 403


def test_delete_missing_incident(client):
    assert client.delete("/incidents/77", headers=ADMIN).status_code == 404


@pytest.mark.parametrize("headers", [{}, {"X-API-Key": "wrong"}])
def test_requests_without_valid_key_are_rejected(client, headers):
    assert client.get("/incidents", headers=headers).status_code == 401


# --- reporting -----------------------------------------------------------

def test_stats(client, sample_incident):
    create(client, sample_incident)
    create(client, {**sample_incident, "severity": "CRITICAL"})
    create(client, {**sample_incident, "status": "RESOLVED"})
    stats = client.get("/stats", headers=ANALYST).json()
    assert stats["total"] == 3
    assert stats["open_by_severity"] == {"HIGH": 1, "CRITICAL": 1}
    assert stats["by_status"] == {"OPEN": 2, "RESOLVED": 1}
    assert stats["highest_risk"] == 90


def test_audit_log_records_changes(client, sample_incident):
    created = create(client, sample_incident)
    client.put(f"/incidents/{created['id']}", json={"status": "RESOLVED"}, headers=ANALYST)
    client.delete(f"/incidents/{created['id']}", headers=ADMIN)

    entries = client.get("/audit", headers=ADMIN).json()
    assert [e["action"] for e in entries] == ["deleted", "updated", "created"]
    assert entries[1]["details"] == "status=RESOLVED"
    assert entries[0]["actor"] == "admin"


def test_audit_log_is_admin_only(client):
    assert client.get("/audit", headers=ANALYST).status_code == 403


def test_open_gauge_follows_incidents(client, sample_incident):
    create(client, {**sample_incident, "severity": "CRITICAL"})
    create(client, {**sample_incident, "severity": "CRITICAL"})
    body = client.get("/metrics").text
    assert 'secureflow_incidents_open{severity="CRITICAL"} 2.0' in body
