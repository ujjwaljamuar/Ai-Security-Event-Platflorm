from datetime import datetime, timedelta, timezone

import jwt
from fastapi.testclient import TestClient

from app.api.main import app
from app.common.config import get_settings


client = TestClient(app)


def make_token(role="analyst", **overrides):
    settings = get_settings()
    now = datetime.now(timezone.utc)

    claims = {
        "sub": "test-user",
        "role": role,
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": now,
        "exp": now + timedelta(minutes=5),
    }
    claims.update(overrides)

    return jwt.encode(
        claims,
        settings.jwt_secret,
        algorithm="HS256",
    )


def test_health_is_public():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_missing_token_is_rejected():
    response = client.get("/api/v1/me")

    assert response.status_code == 401


def test_analyst_can_access_own_identity(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "test-secret-" + "x" * 40)

    # Ensure settings are loaded after the test environment is configured.
    from app.common.config import get_settings

    get_settings.cache_clear()

    try:
        token = make_token(role="analyst")
        response = client.get(
            "/api/v1/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        assert response.json()["role"] == "analyst"
    finally:
        get_settings.cache_clear()


def test_analyst_cannot_access_admin_endpoint(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "test-secret-" + "x" * 40)

    from app.common.config import get_settings

    get_settings.cache_clear()

    try:
        token = make_token(role="analyst")
        response = client.get(
            "/api/v1/admin/check",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 403
    finally:
        get_settings.cache_clear()


def test_expired_token_is_rejected(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "test-secret-" + "x" * 40)

    from app.common.config import get_settings

    get_settings.cache_clear()

    try:
        token = make_token(exp=datetime.now(timezone.utc) - timedelta(minutes=1))
        response = client.get(
            "/api/v1/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 401
    finally:
        get_settings.cache_clear()
