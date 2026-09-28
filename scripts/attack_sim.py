#!/usr/bin/env python3
"""Attack simulator for SecureFlow.

Fires a set of common web attacks at a SecureFlow instance so we can prove
the detector blocks them - used as a post-deploy check and for the incident
drill that triggers the "attack wave" alert.

Only point this at environments you own. By default it refuses to run
against anything except the local lab hosts.

    python scripts/attack_sim.py --target http://localhost:8001
    python scripts/attack_sim.py --target http://secureflow-prod:8000 --rounds 5
"""

import argparse
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

LAB_HOSTS = {"localhost", "127.0.0.1", "secureflow-staging", "secureflow-prod", "host.docker.internal"}

# (name, path, query, user-agent, expected attack_type)
ATTACKS = [
    ("SQL injection", "/incidents", "source=' OR 1=1--", None, "sql_injection"),
    ("UNION based SQLi", "/incidents", "id=1 UNION SELECT username,password FROM users", None, "sql_injection"),
    ("Stored XSS", "/incidents", "q=<script>document.location='http://evil.test'</script>", None, "xss"),
    ("Path traversal", "/files/../../etc/passwd", "", None, "path_traversal"),
    ("Command injection", "/incidents", "host=127.0.0.1; cat /etc/shadow", None, "command_injection"),
    ("Recon: .env", "/.env", "", None, "recon"),
    ("Recon: wp-admin", "/wp-admin/", "", None, "recon"),
    ("Scanner UA", "/incidents", "", "sqlmap/1.8.2#stable (https://sqlmap.org)", "scanner"),
]


def send(url, user_agent=None, api_key=None):
    req = urllib.request.Request(url, headers={"User-Agent": user_agent or "attack-sim/1.0"})
    if api_key:
        req.add_header("X-API-Key", api_key)
    try:
        with urllib.request.urlopen(req, timeout=5) as res:  # nosec B310 - lab targets only
            return res.status, res.read().decode()
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode()


def run(target, rounds, delay):
    blocked = missed = 0
    for round_no in range(1, rounds + 1):
        print(f"\n--- round {round_no}/{rounds} against {target}")
        for name, path, query, agent, expected in ATTACKS:
            url = target + urllib.parse.quote(path, safe="/.")
            if query:
                url += "?" + urllib.parse.quote(query, safe="=&")
            status, body = send(url, agent)
            ok = status == 403 and expected in body
            blocked += ok
            missed += not ok
            print(f"  {'BLOCKED' if ok else 'MISSED '}  {status}  {name}")
            time.sleep(delay)

        # brute force: a handful of wrong API keys in a row
        codes = [send(f"{target}/incidents", api_key=f"guess-{i}")[0] for i in range(6)]
        print(f"  {'DONE   ' if all(c == 401 for c in codes) else 'ODD    '}  401  Brute force x6 {codes}")

    print(f"\nblocked {blocked}, missed {missed}")
    return missed


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default="http://localhost:8000")
    parser.add_argument("--rounds", type=int, default=1)
    parser.add_argument("--delay", type=float, default=0.2, help="seconds between requests")
    parser.add_argument("--i-own-this-target", action="store_true",
                        help="allow a host outside the local lab")
    args = parser.parse_args()

    host = urllib.parse.urlparse(args.target).hostname
    if host not in LAB_HOSTS and not args.i_own_this_target:
        sys.exit(f"refusing to attack '{host}' - only lab hosts are allowed without --i-own-this-target")

    missed = run(args.target.rstrip("/"), args.rounds, args.delay)
    sys.exit(1 if missed else 0)


if __name__ == "__main__":
    main()
