from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_analyze_rejects_invalid_url():
    response = client.post("/api/analyze", json={"url": "mailto:user@example.com"})

    assert response.status_code == 400


def test_analyze_accepts_demo_mode():
    response = client.post(
        "/api/analyze",
        json={"url": "https://onefimesecret.com/", "demo_mode": True},
    )

    payload = response.json()

    assert response.status_code == 200
    assert payload["demo_mode"] is True
    assert payload["score_breakdown"]["categories"]["domain_risk"] == 35


def test_brands_endpoint_returns_watchlist():
    response = client.get("/api/brands")

    payload = response.json()

    assert response.status_code == 200
    assert payload["count"] > 0
    assert payload["brands"]["onetimesecret"] == "onetimesecret.com"
