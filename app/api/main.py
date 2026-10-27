from typing import Annotated
import time

from fastapi import Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from app.observability.metrics import (
    API_REQUESTS,
    API_REQUEST_DURATION,
)

from fastapi import Depends, FastAPI

from app.api.auth import Principal, get_current_user, require_role
from app.api.alerts import router as alerts_router
from app.api.alert_actions import router as alert_actions_router
from app.api.audit import router as audit_router


app = FastAPI(
    title="AI-Assisted Security Event Detection API",
    version="0.1.0",
    description="Security alerts, risk assessments, and analyst workflows.",
)


@app.middleware("http")
async def collect_api_metrics(request: Request, call_next):
    if request.url.path == "/metrics":
        return await call_next(request)

    started = time.perf_counter()
    status_code = 500

    try:
        response = await call_next(request)
        status_code = response.status_code
        return response
    finally:
        duration = time.perf_counter() - started
        API_REQUESTS.labels(
            method=request.method,
            status=str(status_code),
        ).inc()
        API_REQUEST_DURATION.labels(
            method=request.method,
        ).observe(duration)


@app.get("/metrics", include_in_schema=False)
def metrics():
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )


app.include_router(alerts_router)
app.include_router(alert_actions_router)
app.include_router(audit_router)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/api/v1/me")
def get_me(
    principal: Annotated[Principal, Depends(get_current_user)],
):
    return {
        "subject": principal.subject,
        "role": principal.role,
    }


@app.get("/api/v1/admin/check")
def admin_check(
    principal: Annotated[Principal, Depends(require_role("admin"))],
):
    return {"message": "Admin access granted"}
