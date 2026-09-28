import pytest

from app.detector import BruteForceTracker, brute_force_detection, inspect_request

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "path, query, expected",
    [
        ("/incidents", "source=' OR 1=1--", "sql_injection"),
        ("/incidents", "id=1 UNION SELECT username, password FROM users", "sql_injection"),
        ("/incidents", "q=1; DROP TABLE incidents", "sql_injection"),
        ("/incidents", "q=1' AND SLEEP(5)", "sql_injection"),
        ("/incidents", "q=%27%20OR%20%271%27%3D%271", "sql_injection"),  # url-encoded
        ("/incidents", "q=<script>alert(1)</script>", "xss"),
        ("/incidents", "q=<img src=x onerror=alert(1)>", "xss"),
        ("/files", "name=../../etc/passwd", "path_traversal"),
        ("/files/..%2F..%2Fetc%2Fpasswd", "", "path_traversal"),
        ("/incidents", "host=8.8.8.8; cat /etc/hosts", "command_injection"),
        ("/incidents", "x=$(whoami)", "command_injection"),
        ("/.env", "", "recon"),
        ("/wp-admin/install.php", "", "recon"),
        ("/.git/config", "", "recon"),
    ],
)
def test_attacks_are_detected(path, query, expected):
    detection = inspect_request(path, query)
    assert detection is not None
    assert detection.attack_type == expected


@pytest.mark.parametrize(
    "path, query",
    [
        ("/incidents", ""),
        ("/incidents", "severity=HIGH&status=OPEN"),
        ("/incidents", "source=Web Application"),
        ("/incidents/42", ""),
        ("/stats", ""),
        ("/docs", ""),
        ("/incidents", "source=O'Brien's laptop"),  # apostrophes on their own are fine
    ],
)
def test_normal_requests_are_not_flagged(path, query):
    assert inspect_request(path, query, "Mozilla/5.0") is None


@pytest.mark.parametrize("agent", ["sqlmap/1.7.2#stable", "Mozilla/5.00 (Nikto/2.1.6)", "gobuster/3.6"])
def test_scanner_user_agents(agent):
    detection = inspect_request("/incidents", "", agent)
    assert detection.attack_type == "scanner"
    assert detection.severity == "MEDIUM"


def test_most_severe_attack_wins():
    # contains both SQLi and command injection - command injection is worse
    detection = inspect_request("/x", "a=' OR 1=1; cat /etc/passwd")
    assert detection.attack_type == "command_injection"
    assert detection.severity == "CRITICAL"


def test_evidence_is_truncated():
    detection = inspect_request("/x", "q=<script>" + "A" * 1000)
    assert len(detection.evidence) <= 200


def test_brute_force_triggers_once_at_threshold():
    tracker = BruteForceTracker(threshold=3, window_seconds=60)
    results = [tracker.record_failure("10.0.0.5", now=t) for t in (0, 1, 2, 3, 4)]
    assert results == [False, False, True, False, False]


def test_brute_force_window_slides():
    tracker = BruteForceTracker(threshold=3, window_seconds=10)
    tracker.record_failure("10.0.0.5", now=0)
    tracker.record_failure("10.0.0.5", now=1)
    # the first two have expired by now, so this is attempt #1 again
    assert tracker.record_failure("10.0.0.5", now=30) is False
    assert tracker.failures("10.0.0.5") == 1


def test_brute_force_is_tracked_per_ip():
    tracker = BruteForceTracker(threshold=2, window_seconds=60)
    tracker.record_failure("10.0.0.1", now=0)
    assert tracker.record_failure("10.0.0.2", now=1) is False
    assert tracker.record_failure("10.0.0.1", now=2) is True


def test_tracker_reset():
    tracker = BruteForceTracker(threshold=2)
    tracker.record_failure("10.0.0.1")
    tracker.reset()
    assert tracker.failures("10.0.0.1") == 0


def test_brute_force_detection_details():
    detection = brute_force_detection("10.0.0.9", 5)
    assert detection.severity == "HIGH"
    assert "10.0.0.9" in detection.evidence
