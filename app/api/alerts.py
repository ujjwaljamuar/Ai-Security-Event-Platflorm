from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query

from app.api.dependencies import AlertStore, CurrentAnalyst

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])

Severity = Literal["low", "medium", "high", "critical"]
AlertState = Literal["open", "acknowledged", "resolved"]


def public_alert(alert: dict) -> dict:
    """Expose approved alert fields, excluding internal worker metadata."""
    return {
        "alert_id": alert["alert_id"],
        "rule_id": alert["rule_id"],
        "severity": alert["severity"],
        "risk_score": alert["risk_score"],
        "source_ip": alert["source_ip"],
        "event_count": alert["event_count"],
        "first_seen": alert["first_seen"],
        "last_seen": alert["last_seen"],
        "status": alert["status"],
        "summary_status": alert["summary_status"],
        "summary": alert["summary"],
        "evidence": alert["evidence"],
    }


@router.get("")
def list_alerts(
    store: AlertStore,
    principal: CurrentAnalyst,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    severity: Severity | None = None,
    status: AlertState | None = None,
):
    alerts = store.list_alerts(
        limit=limit,
        offset=offset,
        severity=severity,
        status=status,
    )
    return {
        "items": [public_alert(alert) for alert in alerts],
        "limit": limit,
        "offset": offset,
    }


@router.get("/{alert_id}")
def get_alert(
    alert_id: str,
    store: AlertStore,
    principal: CurrentAnalyst,
):
    alert = store.get_alert(alert_id)

    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    return public_alert(alert)
