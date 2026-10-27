from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.api.auth import Principal, require_role
from app.api.dependencies import AlertStore
from app.api.alerts import public_alert

router = APIRouter(prefix="/api/v1/alerts", tags=["alert-actions"])


class AlertStatusUpdate(BaseModel):
    status: Literal["acknowledged", "resolved"]


AnalystOrAdmin = Annotated[
    Principal,
    Depends(require_role("analyst", "admin")),
]

AdminOnly = Annotated[
    Principal,
    Depends(require_role("admin")),
]


@router.patch("/{alert_id}/status")
def update_alert_status(
    alert_id: str,
    request: AlertStatusUpdate,
    store: AlertStore,
    principal: AnalystOrAdmin,
):
    if request.status == "resolved" and principal.role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Only admins can resolve alerts",
        )

    try:
        alert = store.transition_alert(
            alert_id=alert_id,
            new_status=request.status,
            actor_sub=principal.subject,
            actor_role=principal.role,
        )
        return public_alert(alert)

    except LookupError:
        raise HTTPException(status_code=404, detail="Alert not found")

    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
