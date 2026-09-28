"""SLA and risk rules.

Response targets are loosely based on what a small SOC would agree to:
a CRITICAL incident has to be picked up within the hour, a LOW one can
wait a few days.
"""

from datetime import datetime, timedelta, timezone

SLA_HOURS = {
    "CRITICAL": 1,
    "HIGH": 4,
    "MEDIUM": 24,
    "LOW": 72,
}

BASE_RISK = {
    "CRITICAL": 90,
    "HIGH": 60,
    "MEDIUM": 30,
    "LOW": 10,
}


def sla_due_at(severity: str, created_at: datetime) -> datetime:
    return created_at + timedelta(hours=SLA_HOURS[severity])


def is_overdue(severity: str, status: str, created_at: datetime, now: datetime | None = None) -> bool:
    if status == "RESOLVED":
        return False
    now = now or datetime.now(timezone.utc)
    return now > sla_due_at(severity, created_at)


def risk_score(severity: str, status: str, created_at: datetime, now: datetime | None = None) -> int:
    """0-100. Resolved incidents carry no risk, overdue ones get bumped."""
    if status == "RESOLVED":
        return 0
    score = BASE_RISK[severity]
    if is_overdue(severity, status, created_at, now):
        score += 10
    return min(score, 100)
