from fastapi.testclient import TestClient

from app.api.main import app

client = TestClient(app)


def test_metrics_endpoint_returns_prometheus_format():
    response = client.get("/metrics")

    assert response.status_code == 200
    assert "security_api_requests_total" in response.text
    assert "security_api_request_duration_seconds" in response.text


def test_health_request_is_counted():
    client.get("/health")

    metrics_response = client.get("/metrics")

    assert metrics_response.status_code == 200
    assert 'method="GET"' in metrics_response.text
    assert "security_api_requests" in metrics_response.text
