"""Prometheus metrics.

Each app instance gets its own registry so tests (which build a fresh app
every time) don't trip over "duplicated timeseries" errors.
"""

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
ATTACK_TYPES = (
    "command_injection", "sql_injection", "path_traversal", "xss",
    "scanner", "recon", "brute_force",
)


class Metrics:
    def __init__(self, app_version: str, app_env: str):
        self.registry = CollectorRegistry()

        self.requests = Counter(
            "secureflow_http_requests_total", "HTTP requests handled",
            ["method", "path", "status"], registry=self.registry,
        )
        self.latency = Histogram(
            "secureflow_http_request_duration_seconds", "Request latency",
            ["path"], registry=self.registry,
            buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5),
        )
        self.attacks = Counter(
            "secureflow_attacks_detected_total", "Attacks detected and blocked",
            ["attack_type"], registry=self.registry,
        )
        self.incidents_open = Gauge(
            "secureflow_incidents_open", "Open (unresolved) incidents",
            ["severity"], registry=self.registry,
        )
        self.incidents_overdue = Gauge(
            "secureflow_incidents_overdue", "Unresolved incidents past their SLA",
            registry=self.registry,
        )
        self.info = Gauge(
            "secureflow_app_info", "Build information",
            ["version", "env"], registry=self.registry,
        )
        self.info.labels(version=app_version, env=app_env).set(1)

        # make sure every series exists from the start - makes the
        # Grafana panels and alert rules much less awkward
        for severity in SEVERITIES:
            self.incidents_open.labels(severity=severity).set(0)
        # counters too: Prometheus' increase() can't see the jump from "no series"
        # to 24 on the first attack, so without this the AttackWave alert would
        # miss the very first wave after a fresh deployment
        for attack_type in ATTACK_TYPES:
            self.attacks.labels(attack_type=attack_type).inc(0)

    def refresh_incident_gauges(self, open_by_severity: dict, overdue: int) -> None:
        for severity in SEVERITIES:
            self.incidents_open.labels(severity=severity).set(open_by_severity.get(severity, 0))
        self.incidents_overdue.set(overdue)

    def render(self) -> bytes:
        return generate_latest(self.registry)
