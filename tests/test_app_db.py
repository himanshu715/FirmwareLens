from services import app_db


def test_create_and_authenticate_user(tmp_path, monkeypatch):
    test_db = tmp_path / "sentinel.db"
    monkeypatch.setattr(app_db, "DB_PATH", test_db)
    app_db.init_db()

    created = app_db.create_user("alice", "secret123")
    authenticated = app_db.authenticate_user("alice", "secret123")

    assert created["username"] == "alice"
    assert authenticated["username"] == "alice"


def test_feedback_and_bot_messages_are_persisted(tmp_path, monkeypatch):
    test_db = tmp_path / "sentinel.db"
    monkeypatch.setattr(app_db, "DB_PATH", test_db)
    app_db.init_db()

    user = app_db.create_user("bob", "pw12345")
    app_db.save_feedback(user["id"], 5, "bot", "Helpful bot response")
    app_db.save_bot_message(user["id"], None, "Why is my device crashing?", "Collect reset reason first.")

    messages = app_db.get_recent_bot_messages(user["id"])

    assert messages
    assert messages[0]["user_message"] == "Why is my device crashing?"


def test_scan_records_are_persisted(tmp_path, monkeypatch):
    test_db = tmp_path / "sentinel.db"
    monkeypatch.setattr(app_db, "DB_PATH", test_db)
    app_db.init_db()

    user = app_db.create_user("carol", "password123")
    app_db.save_scan_record("12345678-1234-1234-1234-1234567890ab", user["id"], "firmware.bin", "stored.bin")

    record = app_db.get_scan_record("12345678-1234-1234-1234-1234567890ab")

    assert record is not None
    assert record["user_id"] == user["id"]
    assert record["original_filename"] == "firmware.bin"
