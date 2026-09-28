from datetime import datetime, timedelta, timezone

import pytest

from app import sla

pytestmark = pytest.mark.unit

NOW = datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize("severity, hours", [("CRITICAL", 1), ("HIGH", 4), ("MEDIUM", 24), ("LOW", 72)])
def test_sla_deadlines(severity, hours):
    assert sla.sla_due_at(severity, NOW) == NOW + timedelta(hours=hours)


def test_critical_is_overdue_after_an_hour():
    created = NOW - timedelta(minutes=61)
    assert sla.is_overdue("CRITICAL", "OPEN", created, now=NOW) is True


def test_low_is_not_overdue_after_a_day():
    created = NOW - timedelta(hours=24)
    assert sla.is_overdue("LOW", "OPEN", created, now=NOW) is False


def test_resolved_incidents_are_never_overdue():
    created = NOW - timedelta(days=30)
    assert sla.is_overdue("CRITICAL", "RESOLVED", created, now=NOW) is False


@pytest.mark.parametrize("severity, expected", [("CRITICAL", 90), ("HIGH", 60), ("MEDIUM", 30), ("LOW", 10)])
def test_base_risk_score(severity, expected):
    assert sla.risk_score(severity, "OPEN", NOW, now=NOW) == expected


def test_overdue_adds_risk_but_caps_at_100():
    old = NOW - timedelta(days=2)
    assert sla.risk_score("HIGH", "INVESTIGATING", old, now=NOW) == 70
    assert sla.risk_score("CRITICAL", "OPEN", old, now=NOW) == 100


def test_resolved_has_no_risk():
    assert sla.risk_score("CRITICAL", "RESOLVED", NOW, now=NOW) == 0
