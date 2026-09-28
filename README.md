# SecureFlow

**Security incident management API with built-in attack detection.**

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

Python 3.12 · FastAPI · SQLite · Pytest · Docker

## Run it locally

```powershell
python -m venv .venv
.venv\Scripts\activate          # macOS/Linux: source .venv/bin/activate
pip install -r requirements-dev.txt
uvicorn app.main:app --reload
```

- Dashboard: http://localhost:8000 (dev key: `analyst-dev-key`)
- Swagger docs: http://localhost:8000/docs

## Run the tests

```powershell
pytest --cov=app
```

82 tests (unit + integration), ~99% coverage.

## Run it with Docker

```powershell
docker build -t secureflow:dev .
docker run -d --name secureflow -p 8000:8000 secureflow:dev
curl http://localhost:8000/health
```

## Try the detector

With the app running, in another terminal:

```powershell
python scripts/attack_sim.py --target http://localhost:8000
```

Every attack should come back `BLOCKED`, and the dashboard fills up with **AUTO** incidents.

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

Send the key in an `X-API-Key` header. Keys are set with the `ANALYST_API_KEY` and
`ADMIN_API_KEY` environment variables.

## Project layout

```
app/
  main.py        routes + detection middleware
  detector.py    attack patterns and brute-force tracking
  sla.py         response deadlines and risk score
  database.py    SQLite storage + audit log
  auth.py        API keys and roles
  metrics.py     Prometheus metrics
  static/        dashboard
tests/           unit + integration tests
scripts/         attack simulator
```

## Roadmap

- [x] Incident API, detection, dashboard, tests, Docker image
- [ ] Jenkins pipeline: Build → Test → Code Quality → Security → Deploy → Release → Monitoring

## A note on the attack simulator

`scripts/attack_sim.py` only sends well-known test payloads and refuses to run against anything
other than local hosts unless you explicitly say you own the target. It exists to prove the
detector works - please don't point it at systems you don't own.
