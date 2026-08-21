import time
import uuid

import structlog
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from opentelemetry import propagate
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.trace import SpanKind
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from sqlalchemy import text
from sqlalchemy.orm import Session
from starlette.middleware.base import RequestResponseEndpoint

from .audit import write_audit_event
from .auth import current_principal
from .canonical_api import router as canonical_asset_router
from .changes_api import router as changes_router
from .config import get_settings
from .db import get_session
from .discovery_api import router as discovery_router
from .evidence_api import router as evidence_router
from .findings_api import router as findings_router
from .governance_api import router as governance_router
from .jobs import get_celery_client
from .logging import configure_logging
from .models import Membership, Organization
from .observability import configure_tracing, trace_identifiers
from .phase7_api import router as phase7_router
from .security import (
    OrganizationContext,
    Principal,
    organization_header,
    require_org_context,
    require_role,
)

configure_logging()
settings = get_settings()
logger = structlog.get_logger(__name__)
tracer = configure_tracing(settings, "exposure360-api")
celery_client = get_celery_client(settings)
app = FastAPI(title="Exposure360 Phase 1 API", version="0.1.0", openapi_url="/api/v1/openapi.json")
app.include_router(governance_router)
app.include_router(discovery_router)
app.include_router(evidence_router)
app.include_router(canonical_asset_router)
app.include_router(findings_router)
app.include_router(changes_router)
app.include_router(phase7_router)
FastAPIInstrumentor.instrument_app(app)
HTTP_REQUESTS = Counter(
    "exposure360_http_requests_total", "HTTP requests", ["method", "route", "status"]
)
HTTP_DURATION = Histogram(
    "exposure360_http_request_duration_seconds", "HTTP request duration", ["route"]
)
INFLIGHT = Gauge("exposure360_http_inflight", "In-flight HTTP requests")
PROBE_ENQUEUED = Counter(
    "exposure360_worker_tasks_enqueued_total", "Enqueued safe worker probe tasks", ["task"]
)


@app.middleware("http")
async def correlation_id(request: Request, call_next: RequestResponseEndpoint) -> Response:
    correlation = request.headers.get("X-Correlation-ID") or str(uuid.uuid4())
    request.state.correlation_id = correlation
    started = time.perf_counter()
    INFLIGHT.inc()
    with tracer.start_as_current_span(
        "exposure360.http.request", kind=SpanKind.SERVER
    ) as request_span:
        trace_id, span_id = trace_identifiers(request_span)
        structlog.contextvars.bind_contextvars(
            correlation_id=correlation,
            trace_id=trace_id,
            span_id=span_id,
            service="api",
            environment=settings.app_env,
        )
        try:
            response = await call_next(request)
        except Exception:
            response = JSONResponse(
                status_code=500,
                content={
                    "error": {
                        "code": "INTERNAL_ERROR",
                        "message": "Internal server error",
                        "correlation_id": correlation,
                    }
                },
            )
        finally:
            INFLIGHT.dec()
    route = request.scope.get("route")
    route_path = getattr(route, "path", "unmatched")
    duration = time.perf_counter() - started
    HTTP_DURATION.labels(route=route_path).observe(duration)
    HTTP_REQUESTS.labels(
        method=request.method, route=route_path, status=str(response.status_code)
    ).inc()
    response.headers["X-Correlation-ID"] = correlation
    logger.info(
        "http_request_completed",
        route=route_path,
        method=request.method,
        status_code=response.status_code,
        duration_ms=round(duration * 1000, 2),
    )
    structlog.contextvars.clear_contextvars()
    return response


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "live"}


@app.get("/health/ready")
def ready(session: Session = Depends(get_session)) -> dict[str, object]:
    try:
        session.execute(text("SELECT 1"))
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc
    return {
        "status": "ready",
        "dependencies": {"database": "ok", "redis": "configured", "objectstore": "configured"},
    }


@app.get("/metrics")
def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/api/v1/system/info")
def system_info() -> dict[str, object]:
    return {"name": "Exposure360", "version": "0.1.0", "phase": 1, "api_version": "v1"}


@app.get("/api/v1/me")
def me(
    principal: Principal = Depends(current_principal), session: Session = Depends(get_session)
) -> dict[str, object]:
    memberships = (
        session.query(Membership, Organization)
        .join(Organization, Membership.organization_id == Organization.id)
        .filter(Membership.user_id == principal.user.id, Membership.is_active.is_(True))
        .all()
    )
    return {
        "id": str(principal.user.id),
        "subject": principal.user.oidc_subject,
        "display_name": principal.user.display_name,
        "email": principal.user.email,
        "memberships": [
            {
                "organization_id": str(membership.organization_id),
                "organization_name": organization.name,
                "role": membership.role,
            }
            for membership, organization in memberships
        ],
    }


@app.get("/api/v1/organizations/context")
def organization_context(
    organization_id: str | None = Depends(organization_header),
    principal: Principal = Depends(current_principal),
    session: Session = Depends(get_session),
) -> dict[str, str]:
    context = require_org_context(session, principal, organization_id)
    return {
        "organization_id": str(context.organization_id),
        "role": context.membership.role,
    }


@app.post("/api/v1/organizations/memberships/{membership_id}/deactivate")
def deactivate_membership(
    membership_id: str,
    request: Request,
    organization_id: str | None = Depends(organization_header),
    principal: Principal = Depends(current_principal),
    session: Session = Depends(get_session),
) -> dict[str, str]:
    context: OrganizationContext = require_org_context(session, principal, organization_id)
    require_role(context, "owner", "admin")
    target = session.get(Membership, uuid.UUID(membership_id))
    if target is None or target.organization_id != context.organization_id:
        raise HTTPException(status_code=404, detail="Membership not found")
    target.is_active = False
    write_audit_event(
        session,
        context,
        principal,
        action="membership.deactivate",
        resource_type="membership",
        resource_id=membership_id,
        correlation_id=request.state.correlation_id,
        trace_id=trace_identifiers()[0],
        result="success",
    )
    session.commit()
    return {"status": "deactivated"}


@app.post("/api/v1/observability/probe")
def enqueue_observability_probe(
    request: Request,
    principal: Principal = Depends(current_principal),
    session: Session = Depends(get_session),
) -> dict[str, str]:
    correlation_id = request.state.correlation_id
    with tracer.start_as_current_span("observability_probe.api") as probe_span:
        with tracer.start_as_current_span("observability_probe.database"):
            session.execute(text("SELECT 1"))
        carrier: dict[str, str] = {}
        propagate.inject(carrier)
        task = celery_client.send_task(
            "exposure360_worker.tasks.observability_probe",
            kwargs={"correlation_id": correlation_id, "trace_headers": carrier},
        )
        PROBE_ENQUEUED.labels(task="observability_probe").inc()
        trace_id, _ = trace_identifiers(probe_span)
        logger.info(
            "observability_probe_enqueued",
            correlation_id=correlation_id,
            trace_id=trace_id,
            user_id=str(principal.user.id),
            job_id=task.id,
        )
    return {"task_id": task.id, "correlation_id": correlation_id}
