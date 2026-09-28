# SecureFlow

**Security incident management API with built-in attack detection, delivered through a 7-stage Jenkins pipeline.**

Small security teams get alerts from everywhere - WAF logs, phishing reports, failed logins - and
usually end up tracking them in a spreadsheet. SecureFlow gives them one place to log, triage and
resolve incidents, with response deadlines (SLAs) and a risk score for each one.

It also watches its own traffic. When someone tries SQL injection, XSS, path traversal, command
injection, scans it with sqlmap, or brute-forces API keys, SecureFlow blocks the request and
**opens an incident about it automatically**.

```
 attacker ──► GET /incidents?source=' OR 1=1--
                     │
                     ▼
              SecureFlow detector ──► 403 blocked
                     │
                     ├──► new incident: "SQL Injection Attempt" (HIGH, from 172.18.0.5)
                     └──► secureflow_attacks_detected_total{attack_type="sql_injection"} +1
                                         │
                                  Prometheus ──► Alertmanager ──► email to on-call
```

## Features

| | |
|---|---|
| Incidents | Create, list, filter, update and delete incidents (`severity`, `status`, `source`) |
| Roles | API keys for **analyst** (read/write) and **admin** (also delete + audit log) |
| SLA + risk | CRITICAL must be handled in 1h, HIGH 4h, MEDIUM 24h, LOW 72h; overdue incidents are flagged and scored higher |
| Attack detection | SQLi, XSS, path traversal, command injection, scanner user-agents, recon probes (`/.env`, `/wp-admin`), API-key brute force |
| Audit log | Every create/update/delete is recorded with who did it |
| Dashboard | Simple web UI at `/` with live counts, incidents and detections |
| Observability | `/health` for deployments, `/metrics` for Prometheus |

## Tech stack

Python 3.12, FastAPI, SQLite, Pytest · Docker, Docker Compose · Jenkins (configured as code) ·
SonarQube · Bandit, pip-audit, Trivy · Prometheus, Grafana, Alertmanager (Gmail)

## Run it locally (no Docker)

```powershell
python -m venv .venv
.venv\Scripts\activate          # macOS/Linux: source .venv/bin/activate
pip install -r requirements-dev.txt
uvicorn app.main:app --reload
```

Open http://localhost:8000 (dashboard, dev key: `analyst-dev-key`) or http://localhost:8000/docs (Swagger).

Run the tests:

```powershell
pytest --cov=app
```

Try the detector from another terminal:

```powershell
python scripts/attack_sim.py --target http://localhost:8000
```

## API

| Method | Endpoint | Role | |
|---|---|---|---|
| GET | `/health` | public | status, version, environment |
| GET | `/metrics` | public | Prometheus metrics |
| GET | `/incidents` | analyst | filters: `severity`, `status`, `source`, `overdue` |
| GET | `/incidents/{id}` | analyst | |
| POST | `/incidents` | analyst | |
| PUT | `/incidents/{id}` | analyst | partial updates, e.g. `{"status": "RESOLVED"}` |
| DELETE | `/incidents/{id}` | admin | |
| GET | `/stats` | analyst | counts, overdue, highest risk |
| GET | `/audit` | admin | who changed what |

Send the key in an `X-API-Key` header.

## The pipeline

```
 Checkout ─► Build ─► Test ─► Code Quality ─► Security ─► Deploy: Staging ─► Release: Production ─► Monitoring
```

| Stage | What happens | Tools |
|---|---|---|
| **Build** | Versioned Docker image (`1.0.<build>` + git SHA), pushed to a local registry, build info archived | Docker, registry:2 |
| **Test** | Unit and integration tests, JUnit results + HTML coverage report, fails under 80% coverage | Pytest, pytest-cov |
| **Code Quality** | Custom "SecureFlow Gate" (coverage ≥ 80%, duplication ≤ 3%, A ratings), build waits for and enforces the gate | SonarQube |
| **Security** | Code scan, dependency CVEs, secret scan, image scan - fails on anything HIGH/CRITICAL that has a fix ([findings](docs/SECURITY_NOTES.md)) | Bandit, pip-audit, Trivy |
| **Deploy: Staging** | Compose deploy, health + version check, smoke test, attack simulation - **automatic rollback** if unhealthy | Docker Compose, bash |
| **Release: Production** | Image promoted to `v1.0.<build>`, deployed with prod config, git tag + release notes pushed, optional approval gate | Docker Compose, git |
| **Monitoring** | Prometheus/Grafana/Alertmanager deployed from code, scrape targets + alert rules verified, optional incident drills | Prometheus, Grafana, Alertmanager |

Build parameters: `RELEASE_TO_PROD`, `REQUIRE_APPROVAL`, `SIMULATE_BAD_DEPLOY` (rollback demo),
`INCIDENT_DRILL` (`attack-wave` / `staging-outage`).

Full setup (Codespaces or Windows): **[docs/SETUP.md](docs/SETUP.md)** ·
How it all fits together: **[docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md)**

## Where things run

| Service | URL |
|---|---|
| SecureFlow production | http://localhost:8000 |
| SecureFlow staging | http://localhost:8001 |
| Jenkins | http://localhost:8080 |
| SonarQube | http://localhost:9000 |
| Grafana | http://localhost:3000 |
| Prometheus | http://localhost:9090 |
| Alertmanager | http://localhost:9093 |

## Project layout

```
app/            FastAPI app (main, detector, sla, database, auth, metrics, dashboard)
tests/          unit + integration tests
scripts/        deploy/rollback, health + smoke checks, attack simulator, drills
deploy/         staging and production compose files + environment config
monitoring/     Prometheus, Alertmanager, Grafana - all provisioned from code
jenkins/        Jenkins image, plugins and configuration-as-code
Jenkinsfile     the pipeline
```

## A note on the attack simulator

`scripts/attack_sim.py` only sends well-known test payloads and refuses to run against anything
other than the local lab hosts unless you explicitly say you own the target. It exists to prove
the detector works - please don't point it at systems you don't own.
