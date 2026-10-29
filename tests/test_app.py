"""Unit tests for the shortener. CI runs these before the security scans."""
import sys
from pathlib import Path

# Make src/ importable without packaging the project.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from app import create_app  # noqa: E402


def client():
    """A fresh app + test client with an isolated, empty link store per test."""
    return create_app(store={}).test_client()


def test_shorten_then_resolve_redirects():
    c = client()
    resp = c.post("/shorten", json={"url": "https://example.com/page"})
    assert resp.status_code == 201
    code = resp.get_json()["code"]

    # Resolving the code must 302 to the original target.
    r = c.get(f"/r/{code}")
    assert r.status_code == 302
    assert r.headers["Location"] == "https://example.com/page"


def test_rejects_non_http_scheme():
    # javascript: targets must be refused, otherwise this is an open redirect.
    c = client()
    resp = c.post("/shorten", json={"url": "javascript:alert(1)"})
    assert resp.status_code == 400


def test_unknown_code_is_404():
    assert client().get("/r/missing").status_code == 404


def test_codes_are_unique_and_unpredictable():
    # Two shortens of the same URL get different, high-entropy codes.
    c = client()
    a = c.post("/shorten", json={"url": "https://a.test"}).get_json()["code"]
    b = c.post("/shorten", json={"url": "https://a.test"}).get_json()["code"]
    assert a != b
    assert len(a) >= 8  # token_urlsafe(6) encodes to 8 chars
