import pytest

from app import analyzer


@pytest.mark.asyncio
async def test_analyze_url_scores_obvious_phishing_signals(monkeypatch):
    async def fake_redirects(url):
        return {
            "checked": True,
            "status_code": 200,
            "chain": [url],
            "final_url": url,
            "redirect_count": 0,
        }, []

    monkeypatch.setattr(analyzer, "resolve_host_ips", lambda hostname: ["93.184.216.34"])
    monkeypatch.setattr(analyzer, "inspect_redirects", fake_redirects)

    report = await analyzer.analyze_url("http://secure-login-verify.example.com/account")

    assert report["score"] >= 55
    assert report["https"]["uses_https"] is False
    assert report["score_breakdown"]["categories"]["transport_risk"] >= 25
    assert report["score_breakdown"]["categories"]["content_risk"] >= 10
    assert "login" in report["suspicious_keywords"]
    assert report["risk_level"] in {"high", "critical"}


@pytest.mark.asyncio
async def test_private_targets_are_not_requested(monkeypatch):
    called = False

    async def fake_redirects(url):
        nonlocal called
        called = True
        return {}, []

    monkeypatch.setattr(analyzer, "inspect_redirects", fake_redirects)

    report = await analyzer.analyze_url("http://127.0.0.1/admin")

    assert report["safety"]["network_allowed"] is False
    assert report["redirections"]["checked"] is False
    assert report["domain"]["registered_domain_estimate"] == "127.0.0.1"
    assert report["domain"]["subdomain_count"] == 0
    assert called is False


@pytest.mark.asyncio
async def test_lookalike_domain_is_flagged(monkeypatch):
    async def fake_redirects(url):
        return {
            "checked": True,
            "status_code": 200,
            "chain": [url],
            "final_url": url,
            "redirect_count": 0,
        }, []

    monkeypatch.setattr(analyzer, "resolve_host_ips", lambda hostname: ["93.184.216.34"])
    monkeypatch.setattr(analyzer, "inspect_redirects", fake_redirects)

    report = await analyzer.analyze_url("https://onefimesecret.com/")

    assert report["score"] >= 35
    assert report["risk_level"] == "medium"
    assert report["domain"]["brand_lookalikes"][0]["target_brand"] == "onetimesecret"
    assert any(finding["name"] == "brand_impersonation" for finding in report["findings"])


@pytest.mark.asyncio
async def test_demo_mode_skips_network_checks(monkeypatch):
    def fail_resolve(hostname):
        raise AssertionError("DNS resolution should not run in demo mode")

    async def fail_redirects(url):
        raise AssertionError("Redirect checks should not run in demo mode")

    monkeypatch.setattr(analyzer, "resolve_host_ips", fail_resolve)
    monkeypatch.setattr(analyzer, "inspect_redirects", fail_redirects)

    report = await analyzer.analyze_url("https://onefimesecret.com/", demo_mode=True)

    assert report["demo_mode"] is True
    assert report["safety"]["network_allowed"] is False
    assert report["redirections"]["checked"] is False
    assert report["score"] == 35


@pytest.mark.asyncio
async def test_url_shortener_is_flagged(monkeypatch):
    async def fake_redirects(url):
        return {
            "checked": True,
            "status_code": 200,
            "chain": [url],
            "final_url": url,
            "redirect_count": 0,
        }, []

    monkeypatch.setattr(analyzer, "resolve_host_ips", lambda hostname: ["93.184.216.34"])
    monkeypatch.setattr(analyzer, "inspect_redirects", fake_redirects)

    report = await analyzer.analyze_url("https://bit.ly/demo")

    assert report["score_breakdown"]["categories"]["domain_risk"] >= 20
    assert any(finding["name"] == "url_shortener" for finding in report["findings"])


def test_invalid_scheme_is_rejected():
    with pytest.raises(ValueError):
        analyzer.normalize_url("ftp://example.com/file")
