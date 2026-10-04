import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    assert client.get("/api/health").json()["status"] == "ok"


@pytest.mark.parametrize("url", ["http://127.0.0.1/", "http://localhost.", "http://169.254.169.254/latest/meta-data"])
def test_private_targets_rejected(url):
    r = client.post("/api/analyze", json={"url": url})
    assert r.status_code == 400


def test_invalid_url_rejected():
    assert client.post("/api/analyze", json={"url": "not a url"}).status_code == 400


def test_unreachable_domain_degrades_gracefully():
    r = client.post("/api/analyze", json={"url": "https://free-hec-scholarship-apply.xyz/register", "lang": "en"})
    assert r.status_code == 200
    d = r.json()
    assert d["risk_level"] in ("suspicious", "high_risk")
    assert d["confidence"] == "low"
    assert any(x["code"] == "org_impersonation" for x in d["reasons"])
    assert d["explanation_source"] == "fallback"


def test_urdu_output():
    r = client.post("/api/analyze", json={"url": "https://free-hec-scholarship-apply.xyz/", "lang": "ur"})
    assert r.status_code == 200
    assert any("\u0600" <= ch <= "\u06ff" for ch in r.json()["recommendation"])
