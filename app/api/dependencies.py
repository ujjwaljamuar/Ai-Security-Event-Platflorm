from typing import Annotated

from fastapi import Depends

from app.api.auth import Principal, require_role
from app.common.config import get_settings
from app.detection.engine import DetectionEngine
from app.storage.detection_store import DetectionStore


def get_detection_store() -> DetectionStore:
    settings = get_settings()
    return DetectionStore(
        settings.sqlite_path,
        DetectionEngine(
            brute_force_threshold=settings.brute_force_threshold,
            brute_force_window_seconds=settings.brute_force_window_seconds,
        ),
    )


CurrentAnalyst = Annotated[
    Principal,
    Depends(require_role("analyst", "admin")),
]

CurrentAdmin = Annotated[
    Principal,
    Depends(require_role("admin")),
]

AlertStore = Annotated[
    DetectionStore,
    Depends(get_detection_store),
]
