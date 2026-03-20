from config import build_content_security_policy


def test_csp_includes_google_analytics_sources_when_enabled():
    csp = build_content_security_policy(enable_analytics=True)

    assert "https://www.googletagmanager.com" in csp
    assert "https://www.google-analytics.com" in csp


def test_csp_omits_google_analytics_sources_when_disabled():
    csp = build_content_security_policy(enable_analytics=False)

    assert "https://www.googletagmanager.com" not in csp
    assert "https://www.google-analytics.com" not in csp
