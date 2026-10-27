from typing import Annotated

from fastapi import APIRouter, Query

from app.api.dependencies import AlertStore, CurrentAdmin

router = APIRouter(
    prefix="/api/v1/audit-events",
    tags=["audit"],
)


@router.get("")
def list_audit_events(
    store: AlertStore,
    principal: CurrentAdmin,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    resource_id: str | None = None,
):
    return {
        "items": store.list_audit_events(
            limit=limit,
            offset=offset,
            resource_id=resource_id,
        ),
        "limit": limit,
        "offset": offset,
    }
