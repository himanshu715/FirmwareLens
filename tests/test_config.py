import importlib

import config
from config import build_content_security_policy


def test_csp_includes_google_analytics_sources_when_enabled():
    csp = build_content_security_policy(enable_analytics=True)

    assert "https://www.googletagmanager.com" in csp
    assert "https://www.google-analytics.com" in csp


def test_csp_omits_google_analytics_sources_when_disabled():
    csp = build_content_security_policy(enable_analytics=False)

    assert "https://www.googletagmanager.com" not in csp
    assert "https://www.google-analytics.com" not in csp


def test_vercel_uses_tmp_runtime_root(monkeypatch):
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.delenv("RUNTIME_ROOT", raising=False)
    monkeypatch.delenv("MAX_UPLOAD_SIZE_BYTES", raising=False)

    reloaded = importlib.reload(config)

    assert reloaded.RUNTIME_ROOT.as_posix().endswith("/tmp/firmwarelens")
    assert reloaded.MAX_UPLOAD_SIZE == 4 * 1024 * 1024
    assert reloaded.DEPLOYMENT_NOTICE

    monkeypatch.delenv("VERCEL", raising=False)
    importlib.reload(config)
