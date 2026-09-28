# How SecureFlow works

A walkthrough of the code and the pipeline - read this before recording the demo so you can
explain every part in your own words.

## The app, file by file

| File | What it does | Worth mentioning |
|---|---|---|
| `app/main.py` | Creates the FastAPI app, the routes and the middleware | `create_app()` builds a fresh app - that's what lets every test run against its own empty database |
| `app/detector.py` | Pattern checks for SQLi, XSS, traversal, command injection, scanners, recon; brute-force tracker | Checks are ordered by severity, payloads are URL-decoded twice (attackers encode them), incident bodies are deliberately *not* scanned |
| `app/sla.py` | Deadlines per severity and the 0-100 risk score | Pure functions - easiest code in the project to unit test |
| `app/database.py` | SQLite: incidents + audit log | Only parameterised queries; the "dedupe" query stops one attacker creating 500 incidents |
| `app/auth.py` | API keys and the two roles | `hmac.compare_digest` for constant-time comparison |
| `app/metrics.py` | Prometheus counters, gauges, histogram | Route templates (`/incidents/{incident_id}`) as labels, not raw URLs |
| `app/static/` | The dashboard | Plain HTML/JS calling the same API, refreshes every 5 s |

### What happens to a request

1. Middleware looks at the path, query string and User-Agent.
2. If it matches an attack pattern: count it in `/metrics`, create an incident (unless the same
   attacker triggered the same thing in the last 5 minutes), return **403**.
3. Otherwise the route runs. If it ends in **401** (bad API key), the brute-force tracker counts
   it; the 5th failure from one IP within the window opens a "Brute-Force Attack" incident.
4. Request count and latency are recorded for Prometheus.

## The pipeline, stage by stage

**Build** - creates a Python virtualenv, builds the Docker image with the version baked in
(`1.0.<build number>`), tags it with the git SHA too, and pushes both tags to the local registry
on port 5000. That registry is the artifact store: any old version can be redeployed from it.
`build-info.json` is archived with the build.

**Test** - unit tests (detector, SLA) then integration tests (the real API through FastAPI's
test client). JUnit results show up in Jenkins' test tab and the HTML coverage report is linked
on the build page. Under 80% coverage fails the stage.

**Code Quality** - `sonar_quality_gate.sh` makes sure the project and "SecureFlow Gate" exist
(coverage ≥ 80, duplication ≤ 3%, A for reliability/security/maintainability). The scanner runs
with `sonar.qualitygate.wait=true`, so Jenkins waits for SonarQube's verdict and fails if the gate
fails. The static dashboard is excluded (no Node.js on the scanner) and duplication in tests is
ignored - both explained in `sonar-project.properties`.

**Security** - Bandit, pip-audit, Trivy secret scan, Trivy image scan. JSON reports are archived;
the table in `docs/SECURITY_NOTES.md` explains every finding.

**Deploy: Staging** - `deploy.sh` remembers which version is running, starts the new one with
Compose, then polls `/health` until it says `healthy` **and** reports the new version. If that
never happens it redeploys the previous version and fails the build. After that, a smoke test
(create/read/resolve an incident, check auth, check metrics) and the attack simulator (every
attack must be blocked) run against staging.

**Release: Production** - the tested image is re-tagged `v1.0.N` and `latest` (the same bytes
that passed staging - nothing is rebuilt), deployed with the production config (`prod.env`,
production API keys, memory limit) using the same health-check/rollback script, smoke tested,
and then the commit is tagged in GitHub with generated release notes. `REQUIRE_APPROVAL` adds a
manual "Release?" button if you want a human gate.

**Monitoring** - brings up Prometheus, Alertmanager and Grafana (their configs are baked into
images, so changing an alert rule is just a commit), then proves it works: Prometheus is
scraping production, all 7 alert rules are loaded, and the running version is visible. Drills
are optional.

If any stage fails, a `PipelineFailed` alert is pushed into Alertmanager, so broken builds land
in the same inbox as production problems.

## Alert rules

| Alert | Fires when | Why it matters |
|---|---|---|
| SecureFlowDown | a target misses scrapes for 1 min | the service is down |
| HighErrorRate | > 5% of requests are 5xx for 2 min | something is broken for users |
| SlowResponses | p95 latency > 500 ms for 5 min | degraded performance |
| AttackWave | > 10 attacks blocked in 1 min | active attack, not background noise |
| BruteForceDetected | any brute-force detection in 5 min | someone is guessing keys |
| CriticalIncidentsPiling | ≥ 3 CRITICAL incidents open for 1 min | the team is overloaded |
| IncidentsPastSLA | anything overdue for 5 min | response targets are being missed |

Every staging deploy runs an attack test on purpose, so staging's security alerts are routed to a
null receiver - otherwise every build would email you. The one staging alert that still emails is
`SecureFlowDown`. Production alerts always email.

### A monitoring bug we found (and fixed)

The first attack-wave drill against production blocked 24 attacks but **AttackWave never fired**.
The attack counter series only came into existence at the first attack, and Prometheus'
`increase()` can't measure a jump from "no series" to 24 - it needs a starting sample. The fix
was to pre-create every `secureflow_attacks_detected_total{attack_type=...}` series at 0 when the
app starts (`app/metrics.py`), plus a test that guards it. The next drill fired the alert in ~5s,
and the FIRING and RESOLVED emails both arrived.

## Suggested 10-minute demo

| Time | Show |
|---|---|
| 0:00-1:00 | The problem + SecureFlow in one sentence. Dashboard with a few incidents |
| 1:00-2:00 | Repo tour: app, tests, Jenkinsfile, `jenkins/casc.yaml` (Jenkins as code) |
| 2:00-3:00 | Clone + setup: `.env`, `docker compose up`, Jenkins already has the job |
| 3:00-6:30 | Run the pipeline and narrate each stage: image tags, test + coverage report, SonarQube gate, security reports, staging health check, prod release, git tag on GitHub |
| 6:30-7:30 | Rollback demo (`SIMULATE_BAD_DEPLOY`) |
| 7:30-9:30 | Attack drill: run `attack_sim.py`, dashboard fills with AUTO incidents, Grafana spikes, AttackWave email arrives |
| 9:30-10:00 | Wrap-up: what you'd improve next |

## Mapping to the report template

| Report section | Where to get it |
|---|---|
| 3. Stages implemented | 7 (Build, Test, Code Quality, Security, Deploy, Release, Monitoring) |
| 4. Project + technologies | README "Features" + "Tech stack" |
| 5. Pipeline screenshot | Jenkins job page (Stage View) or the "Pipeline Overview" tab |
| 6. Stage descriptions | "The pipeline, stage by stage" above + screenshots from each stage's log |
| Security findings | `docs/SECURITY_NOTES.md` |
