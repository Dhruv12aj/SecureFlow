"""Lightweight attack detection.

This is not trying to be a full WAF - it catches the common, noisy attacks
you see in any web server log (SQLi, XSS, path traversal, command injection,
vulnerability scanners, recon probes) and brute forcing of API keys.

Only the URL path, query string and User-Agent are inspected. Request bodies
of the incident endpoints are deliberately NOT scanned: analysts regularly
paste real payloads into incident descriptions, and blocking them would make
the tool useless for the people it is built for.
"""

import re
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from urllib.parse import unquote_plus


@dataclass(frozen=True)
class Detection:
    attack_type: str
    title: str
    severity: str
    evidence: str


# attack_type -> (incident title, severity)
ATTACK_TYPES = {
    "command_injection": ("Command Injection Attempt", "CRITICAL"),
    "sql_injection": ("SQL Injection Attempt", "HIGH"),
    "path_traversal": ("Path Traversal Attempt", "HIGH"),
    "xss": ("Cross-Site Scripting Attempt", "MEDIUM"),
    "scanner": ("Vulnerability Scanner Detected", "MEDIUM"),
    "recon": ("Reconnaissance Probe", "LOW"),
    "brute_force": ("Brute-Force Attack on API Keys", "HIGH"),
}

_SQLI = re.compile(
    r"(\bunion\b.{0,40}\bselect\b)"
    r"|('|\")\s*(or|and)\s+('|\"|\d)"
    r"|\bor\s+1\s*=\s*1\b"
    r"|;\s*(drop|delete|insert|update)\s+"
    r"|\b(sleep|benchmark|pg_sleep)\s*\("
    r"|'\s*--",
    re.IGNORECASE,
)
_XSS = re.compile(
    r"<\s*script|javascript\s*:|\bon(error|load|click|mouseover)\s*=|<\s*(iframe|svg|img)\b",
    re.IGNORECASE,
)
_TRAVERSAL = re.compile(r"\.\./|\.\.\\|/etc/passwd|/etc/shadow|c:\\windows", re.IGNORECASE)
_CMD = re.compile(
    r"(;|\||&&|`|\$\()\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|powershell|rm)\b",
    re.IGNORECASE,
)
_SCANNER_UA = re.compile(
    r"sqlmap|nikto|nmap|masscan|gobuster|dirbuster|wpscan|nuclei|acunetix|zgrab",
    re.IGNORECASE,
)
RECON_PATHS = (
    "/.env", "/.git", "/wp-admin", "/wp-login.php", "/phpmyadmin",
    "/admin.php", "/config.php", "/server-status", "/.aws", "/actuator",
)

# order matters: report the most serious thing we find
_CHECKS = (
    ("command_injection", _CMD),
    ("sql_injection", _SQLI),
    ("path_traversal", _TRAVERSAL),
    ("xss", _XSS),
)


def _make(attack_type: str, evidence: str) -> Detection:
    title, severity = ATTACK_TYPES[attack_type]
    return Detection(attack_type, title, severity, evidence[:200])


def inspect_request(path: str, query: str = "", user_agent: str = "") -> Detection | None:
    """Return the first (most severe) attack found in the request, or None."""
    # attackers love to URL-encode payloads, so decode twice before matching
    target = unquote_plus(unquote_plus(f"{path}?{query}" if query else path))

    for attack_type, pattern in _CHECKS:
        match = pattern.search(target)
        if match:
            return _make(attack_type, target)

    if user_agent and _SCANNER_UA.search(user_agent):
        return _make("scanner", f"User-Agent: {user_agent}")

    lowered = path.lower()
    if any(lowered.startswith(p) for p in RECON_PATHS):
        return _make("recon", path)

    return None


class BruteForceTracker:
    """Counts failed API-key attempts per IP in a sliding window."""

    def __init__(self, threshold: int = 5, window_seconds: int = 60):
        self.threshold = threshold
        self.window = window_seconds
        self._failures: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def record_failure(self, ip: str, now: float | None = None) -> bool:
        """Returns True exactly once per burst - when the IP hits the threshold."""
        now = now if now is not None else time.monotonic()
        with self._lock:
            attempts = self._failures[ip]
            attempts.append(now)
            while attempts and now - attempts[0] > self.window:
                attempts.popleft()
            return len(attempts) == self.threshold

    def failures(self, ip: str) -> int:
        return len(self._failures.get(ip, ()))

    def reset(self) -> None:
        with self._lock:
            self._failures.clear()


def brute_force_detection(ip: str, attempts: int) -> Detection:
    return _make("brute_force", f"{attempts} invalid API keys from {ip}")
