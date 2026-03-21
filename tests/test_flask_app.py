import io

from services import app_db


def test_support_redirects_to_login_for_invalid_stale_session(tmp_path, monkeypatch):
    test_db = tmp_path / "sentinel.db"
    monkeypatch.setattr(app_db, "DB_PATH", test_db)
    app_db.init_db()

    from app import app

    app.config["TESTING"] = True

    with app.test_client() as client:
        with client.session_transaction() as session:
            session["user"] = {"username": "stale-user"}

        response = client.get("/support")

    assert response.status_code == 302
    assert "/?auth=login" in response.headers["Location"]


def test_support_redirects_to_login_for_string_stale_session(tmp_path, monkeypatch):
    test_db = tmp_path / "sentinel.db"
    monkeypatch.setattr(app_db, "DB_PATH", test_db)
    app_db.init_db()

    from app import app

    app.config["TESTING"] = True

    with app.test_client() as client:
        with client.session_transaction() as session:
            session["user"] = "stale-user"

        response = client.get("/support")

    assert response.status_code == 302
    assert "/?auth=login" in response.headers["Location"]


def test_support_renders_for_valid_user(tmp_path, monkeypatch):
    test_db = tmp_path / "sentinel.db"
    monkeypatch.setattr(app_db, "DB_PATH", test_db)
    app_db.init_db()
    user = app_db.create_user("alice", "secret123")

    from app import app

    app.config["TESTING"] = True

    with app.test_client() as client:
        with client.session_transaction() as session:
            session["user"] = user

        response = client.get("/support")

    assert response.status_code == 200
    assert b"Support Center" in response.data


def test_support_rejects_scan_owned_by_different_user(tmp_path, monkeypatch):
    test_db = tmp_path / "sentinel.db"
    monkeypatch.setattr(app_db, "DB_PATH", test_db)
    app_db.init_db()
    owner = app_db.create_user("owner", "ownerpass123")
    viewer = app_db.create_user("viewer", "viewerpass123")
    app_db.save_scan_record("12345678-1234-1234-1234-1234567890ab", owner["id"], "firmware.bin", "stored.bin")

    from app import app

    app.config["TESTING"] = True

    with app.test_client() as client:
        with client.session_transaction() as session:
            session["user"] = viewer

        response = client.get("/support?scan_id=12345678-1234-1234-1234-1234567890ab")

    assert response.status_code == 403
    assert b"not available under your account" in response.data


def test_home_renders_login_panel_for_guests(tmp_path, monkeypatch):
    test_db = tmp_path / "sentinel.db"
    monkeypatch.setattr(app_db, "DB_PATH", test_db)
    app_db.init_db()

    from app import app

    app.config["TESTING"] = True

    with app.test_client() as client:
        response = client.get("/")

    assert response.status_code == 200
    assert b"Sign In To Start" in response.data
    assert b"Sign In To FirmwareLens" in response.data
    assert b"Firmware Security Scanner for IoT and Embedded Teams" in response.data


def test_support_renders_for_guest_session(tmp_path, monkeypatch):
    test_db = tmp_path / "sentinel.db"
    monkeypatch.setattr(app_db, "DB_PATH", test_db)
    app_db.init_db()

    from app import app

    app.config["TESTING"] = True

    with app.test_client() as client:
        with client.session_transaction() as session:
            session["user"] = {"guest": True, "username": "Guest", "guest_token": "guest-token"}
            session["guest_scans"] = []

        response = client.get("/support")

    assert response.status_code == 200
    assert b"Guest mode" in response.data


def test_robots_txt_exposes_sitemap(tmp_path, monkeypatch):
    test_db = tmp_path / "sentinel.db"
    monkeypatch.setattr(app_db, "DB_PATH", test_db)
    app_db.init_db()

    from app import app

    app.config["TESTING"] = True

    with app.test_client() as client:
        response = client.get("/robots.txt")

    assert response.status_code == 200
    assert b"User-agent: *" in response.data
    assert b"Sitemap:" in response.data
    assert b"Disallow: /support" in response.data
    assert b"Disallow: /download-report" in response.data


def test_ads_txt_returns_404_when_not_configured(tmp_path, monkeypatch):
    test_db = tmp_path / "sentinel.db"
    monkeypatch.setattr(app_db, "DB_PATH", test_db)
    app_db.init_db()

    from app import app

    app.config["TESTING"] = True

    with app.test_client() as client:
        response = client.get("/ads.txt")

    assert response.status_code == 404


def test_support_sets_noindex_header(tmp_path, monkeypatch):
    test_db = tmp_path / "sentinel.db"
    monkeypatch.setattr(app_db, "DB_PATH", test_db)
    app_db.init_db()
    user = app_db.create_user("seo-user", "secret123")

    from app import app

    app.config["TESTING"] = True

    with app.test_client() as client:
        with client.session_transaction() as session:
            session["user"] = user

        response = client.get("/support")

    assert response.status_code == 200
    assert response.headers["X-Robots-Tag"] == "noindex, nofollow, noarchive"


def test_upload_api_accepts_file_without_csrf(tmp_path, monkeypatch):
    test_db = tmp_path / "sentinel.db"
    monkeypatch.setattr(app_db, "DB_PATH", test_db)
    app_db.init_db()

    from app import app

    app.config["TESTING"] = True

    with app.test_client() as client:
        response = client.post(
            "/upload",
            data={"file": (io.BytesIO(b"firmware-data"), "firmware.bin")},
            content_type="multipart/form-data",
            headers={"Origin": "https://firmware-lens.vercel.app"},
        )

    body = response.get_json()
    assert response.status_code == 200
    assert body["message"] == "Firmware uploaded successfully"
    assert body["filename"].endswith(".bin")
    assert response.headers["Access-Control-Allow-Origin"] == "https://firmware-lens.vercel.app"


def test_analyze_json_accepts_upload_without_csrf(tmp_path, monkeypatch):
    test_db = tmp_path / "sentinel.db"
    monkeypatch.setattr(app_db, "DB_PATH", test_db)
    app_db.init_db()

    from app import app
    import app as app_module

    monkeypatch.setattr(
        app_module,
        "analyze_firmware",
        lambda _path: {
            "firmware_type": "BIN",
            "total_strings": 4,
            "score": 88,
            "all_findings_count": 1,
            "top_findings": [],
            "findings": [],
            "summary": {"critical": 0, "high": 0, "medium": 1},
            "breakdown": {
                "secrets": 0,
                "crypto": 0,
                "libraries": 0,
                "suspicious": 1,
                "bad_practices": 0,
            },
            "firmware_info": {"file_type": "BIN", "architecture": "ARM"},
            "revenue": {
                "estimated_revenue_at_risk_usd": 1000,
                "projected_revenue_protected_usd": 750,
                "incident_likelihood_percent": 10,
                "executive_summary": "Summary",
            },
            "ai_agent": {
                "agent_name": "Sentinel Bot",
                "status": "ready",
                "summary": "Summary",
                "triage_stance": "Investigate",
                "priority_actions": ["Review strings"],
                "recommended_next_step": "Check extracted data",
            },
        },
    )
    app.config["TESTING"] = True

    with app.test_client() as client:
        response = client.post(
            "/analyze-json",
            data={"firmware": (io.BytesIO(b"firmware-data"), "firmware.bin")},
            content_type="multipart/form-data",
        )

    body = response.get_json()
    assert response.status_code == 200
    assert body["firmware_type"] == "BIN"
    assert "scan_id" in body


def test_public_analyze_renders_public_report_flow(tmp_path, monkeypatch):
    test_db = tmp_path / "sentinel.db"
    monkeypatch.setattr(app_db, "DB_PATH", test_db)
    app_db.init_db()

    from app import app
    import app as app_module

    monkeypatch.setattr(
        app_module,
        "analyze_firmware",
        lambda _path: {
            "firmware_type": "BIN",
            "total_strings": 4,
            "score": 88,
            "all_findings_count": 1,
            "top_findings": [],
            "findings": [],
            "summary": {"critical": 0, "high": 0, "medium": 1},
            "breakdown": {
                "secrets": 0,
                "crypto": 0,
                "libraries": 0,
                "suspicious": 1,
                "bad_practices": 0,
            },
            "firmware_info": {"file_type": "BIN", "architecture": "ARM"},
            "revenue": {
                "estimated_revenue_at_risk_usd": 1000,
                "projected_revenue_protected_usd": 750,
                "incident_likelihood_percent": 10,
                "executive_summary": "Summary",
            },
            "ai_agent": {
                "agent_name": "Sentinel Bot",
                "status": "ready",
                "summary": "Summary",
                "triage_stance": "Investigate",
                "priority_actions": ["Review strings"],
                "recommended_next_step": "Check extracted data",
            },
        },
    )
    app.config["TESTING"] = True

    with app.test_client() as client:
        response = client.post(
            "/public/analyze",
            data={"firmware": (io.BytesIO(b"firmware-data"), "firmware.bin")},
            content_type="multipart/form-data",
        )

    assert response.status_code == 200
    assert b"Public scan mode" in response.data
    assert b"/public/download-report?scan_id=" in response.data


def test_home_uses_backend_public_upload_when_configured(tmp_path, monkeypatch):
    test_db = tmp_path / "sentinel.db"
    monkeypatch.setattr(app_db, "DB_PATH", test_db)
    app_db.init_db()

    from app import app
    import app as app_module

    monkeypatch.setattr(app_module, "PUBLIC_ANALYZE_URL", "https://firmwarelens.onrender.com/public/analyze")
    monkeypatch.setattr(app_module, "BACKEND_PUBLIC_URL", "https://firmwarelens.onrender.com")
    monkeypatch.setattr(app_module, "PUBLIC_SCAN_MAX_UPLOAD_SIZE", 50 * 1024 * 1024)
    monkeypatch.setattr(app_module, "PUBLIC_SCAN_MAX_UPLOAD_SIZE_MB", 50.0)
    app.config["TESTING"] = True

    with app.test_client() as client:
        response = client.get("/")

    assert response.status_code == 200
    assert b"https://firmwarelens.onrender.com/public/analyze" in response.data
    assert b"Backend upload enabled." in response.data
