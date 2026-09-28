import logging
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app import sla
from app.auth import current_role, require_admin
from app.config import Settings, load_settings
from app.database import Database
from app.detector import BruteForceTracker, Detection, brute_force_detection, inspect_request
from app.metrics import Metrics
from app.schemas import Incident, IncidentCreate, IncidentUpdate, Severity, Status

log = logging.getLogger("secureflow")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

STATIC_DIR = Path(__file__).parent / "static"

# requests we never inspect - monitoring endpoints and the dashboard's own files
SKIP_INSPECTION = ("/health", "/metrics", "/static/")

# one attacker hammering us should update a single incident, not create hundreds
DEDUPE_WINDOW = timedelta(minutes=5)


def _parse(ts: str | None) -> datetime | None:
    return datetime.fromisoformat(ts) if ts else None


def to_incident(row: dict) -> Incident:
    created = _parse(row["created_at"])
    return Incident(
        **{k: row[k] for k in ("id", "title", "severity", "status", "source",
                               "description", "detected_by", "attacker_ip")},
        created_at=created,
        updated_at=_parse(row["updated_at"]),
        resolved_at=_parse(row["resolved_at"]),
        sla_due_at=sla.sla_due_at(row["severity"], created),
        is_overdue=sla.is_overdue(row["severity"], row["status"], created),
        risk_score=sla.risk_score(row["severity"], row["status"], created),
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()

    app = FastAPI(
        title="SecureFlow",
        description="Security incident management API with built-in attack detection.",
        version=settings.app_version,
    )
    app.state.settings = settings
    app.state.db = Database(settings.database_path)
    app.state.metrics = Metrics(settings.app_version, settings.app_env)
    app.state.brute_force = BruteForceTracker(
        settings.brute_force_threshold, settings.brute_force_window_seconds
    )
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    db: Database = app.state.db
    metrics: Metrics = app.state.metrics

    def record_attack(detection: Detection, ip: str) -> None:
        metrics.attacks.labels(attack_type=detection.attack_type).inc()
        log.warning("blocked %s from %s: %s", detection.attack_type, ip, detection.evidence)

        since = (datetime.now(timezone.utc) - DEDUPE_WINDOW).isoformat()
        if db.recent_auto_incident(detection.title, ip, since):
            return
        incident = db.create_incident(
            {
                "title": detection.title,
                "severity": detection.severity,
                "source": "SecureFlow Detector",
                "description": f"Blocked request. Evidence: {detection.evidence}",
            },
            detected_by="auto",
            attacker_ip=ip,
        )
        db.add_audit("auto_created", "detector", incident["id"], detection.attack_type)

    # ---- middleware: detection + metrics --------------------------------

    @app.middleware("http")
    async def inspect_and_measure(request: Request, call_next):
        started = time.perf_counter()
        path = request.url.path
        ip = request.client.host if request.client else "unknown"

        if not path.startswith(SKIP_INSPECTION):
            detection = inspect_request(
                path, request.url.query, request.headers.get("user-agent", "")
            )
            if detection:
                record_attack(detection, ip)
                metrics.requests.labels(request.method, "blocked", "403").inc()
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Request blocked by SecureFlow",
                             "attack_type": detection.attack_type},
                )

        response = await call_next(request)

        if response.status_code == 401:
            tracker = app.state.brute_force
            if tracker.record_failure(ip):
                record_attack(brute_force_detection(ip, tracker.failures(ip)), ip)

        # use the route template (/incidents/{incident_id}) so every id
        # doesn't become its own time series
        route = request.scope.get("route")
        label = getattr(route, "path", "unmatched")
        metrics.requests.labels(request.method, label, str(response.status_code)).inc()
        metrics.latency.labels(label).observe(time.perf_counter() - started)
        return response

    # ---- public endpoints -----------------------------------------------

    @app.get("/", include_in_schema=False)
    def dashboard():
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/health", tags=["monitoring"])
    def health():
        db_ok = db.ping()
        body = {
            "status": "healthy" if db_ok else "unhealthy",
            "version": settings.app_version,
            "environment": settings.app_env,
            "database": "ok" if db_ok else "unreachable",
        }
        return JSONResponse(body, status_code=200 if db_ok else 503)

    @app.get("/metrics", tags=["monitoring"], include_in_schema=False)
    def prometheus_metrics():
        open_rows = [r for r in db.list_incidents() if r["status"] != "RESOLVED"]
        overdue = sum(
            sla.is_overdue(r["severity"], r["status"], _parse(r["created_at"])) for r in open_rows
        )
        metrics.refresh_incident_gauges(db.counts()["open_by_severity"], overdue)
        return Response(metrics.render(), media_type="text/plain; version=0.0.4")

    # ---- incidents ------------------------------------------------------

    @app.get("/incidents", response_model=list[Incident], tags=["incidents"])
    def list_incidents(
        severity: Severity | None = None,
        status_: Status | None = Query(default=None, alias="status"),
        source: str | None = Query(default=None, max_length=80),
        overdue: bool | None = None,
        role: str = Depends(current_role),
    ):
        rows = db.list_incidents(
            severity.value if severity else None,
            status_.value if status_ else None,
            source,
        )
        incidents = [to_incident(r) for r in rows]
        if overdue is not None:
            incidents = [i for i in incidents if i.is_overdue == overdue]
        return incidents

    @app.get("/incidents/{incident_id}", response_model=Incident, tags=["incidents"])
    def get_incident(incident_id: int, role: str = Depends(current_role)):
        row = db.get_incident(incident_id)
        if row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
        return to_incident(row)

    @app.post("/incidents", response_model=Incident, status_code=201, tags=["incidents"])
    def create_incident(payload: IncidentCreate, role: str = Depends(current_role)):
        row = db.create_incident(payload.model_dump(mode="json"))
        db.add_audit("created", role, row["id"], row["title"])
        return to_incident(row)

    @app.put("/incidents/{incident_id}", response_model=Incident, tags=["incidents"])
    def update_incident(incident_id: int, payload: IncidentUpdate, role: str = Depends(current_role)):
        changes = payload.model_dump(mode="json", exclude_none=True)
        row = db.update_incident(incident_id, changes)
        if row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
        if changes:
            summary = ", ".join(f"{k}={v}" for k, v in changes.items() if k != "description")
            db.add_audit("updated", role, incident_id, summary or "description")
        return to_incident(row)

    @app.delete("/incidents/{incident_id}", status_code=204, tags=["incidents"])
    def delete_incident(incident_id: int, role: str = Depends(require_admin)):
        if not db.delete_incident(incident_id):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
        db.add_audit("deleted", role, incident_id)
        return Response(status_code=204)

    # ---- reporting ------------------------------------------------------

    @app.get("/stats", tags=["reporting"])
    def stats(role: str = Depends(current_role)):
        counts = db.counts()
        incidents = [to_incident(r) for r in db.list_incidents()]
        return {
            **counts,
            "total": len(incidents),
            "overdue": sum(i.is_overdue for i in incidents),
            "highest_risk": max((i.risk_score for i in incidents), default=0),
        }

    @app.get("/audit", tags=["reporting"])
    def audit_log(limit: int = Query(default=50, ge=1, le=500), role: str = Depends(require_admin)):
        return db.list_audit(limit)

    return app


app = create_app()
