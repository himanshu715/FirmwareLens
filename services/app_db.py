import re
import sqlite3
from typing import Optional

from werkzeug.security import check_password_hash, generate_password_hash

from config import DB_PATH, ensure_runtime_dirs


ensure_runtime_dirs()

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,64}$")
MAX_CATEGORY_LENGTH = 40
MAX_TITLE_LENGTH = 180
MAX_DEVICE_MODEL_LENGTH = 120
MAX_FIRMWARE_VERSION_LENGTH = 80
MAX_LONG_TEXT_LENGTH = 8000


def get_connection():
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db():
    with get_connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                rating INTEGER,
                category TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS field_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                device_model TEXT,
                firmware_version TEXT,
                symptoms TEXT NOT NULL,
                environment TEXT,
                bot_solution TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS bot_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                scan_id TEXT,
                user_message TEXT NOT NULL,
                bot_response TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                user_id INTEGER,
                original_filename TEXT NOT NULL,
                stored_filename TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE INDEX IF NOT EXISTS idx_feedback_user_id ON feedback(user_id, id);
            CREATE INDEX IF NOT EXISTS idx_field_reports_user_id ON field_reports(user_id, id);
            CREATE INDEX IF NOT EXISTS idx_bot_messages_user_id ON bot_messages(user_id, id);
            """
        )


def create_user(username: str, password: str):
    username = username.strip()
    password = password.strip()

    if not username or not password:
        raise ValueError("Username and password are required.")
    if not USERNAME_PATTERN.fullmatch(username):
        raise ValueError("Username must be 3-64 characters and use only letters, numbers, dots, underscores, or hyphens.")
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")

    password_hash = generate_password_hash(password)

    try:
        with get_connection() as connection:
            cursor = connection.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash),
            )
            return {"id": cursor.lastrowid, "username": username}
    except sqlite3.IntegrityError as error:
        raise ValueError("Username already exists.") from error


def authenticate_user(username: str, password: str) -> Optional[dict]:
    with get_connection() as connection:
        row = connection.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username.strip(),),
        ).fetchone()

    if row and check_password_hash(row["password_hash"], password):
        return {"id": row["id"], "username": row["username"]}

    return None


def get_user_by_id(user_id: int) -> Optional[dict]:
    with get_connection() as connection:
        row = connection.execute(
            "SELECT id, username FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()

    if row:
        return {"id": row["id"], "username": row["username"]}

    return None


def get_user_by_username(username: str) -> Optional[dict]:
    with get_connection() as connection:
        row = connection.execute(
            "SELECT id, username FROM users WHERE username = ?",
            (username.strip(),),
        ).fetchone()

    if row:
        return {"id": row["id"], "username": row["username"]}

    return None


def save_feedback(user_id: int, rating: int, category: str, message: str):
    normalized_category = _normalize_optional_text(category, MAX_CATEGORY_LENGTH) or "general"
    normalized_message = _normalize_required_text(message, MAX_LONG_TEXT_LENGTH)
    normalized_rating = rating if rating in {1, 2, 3, 4, 5} else None

    with get_connection() as connection:
        connection.execute(
            "INSERT INTO feedback (user_id, rating, category, message) VALUES (?, ?, ?, ?)",
            (user_id, normalized_rating, normalized_category, normalized_message),
        )


def save_field_report(user_id: int, title: str, device_model: str, firmware_version: str, symptoms: str, environment: str, bot_solution: str):
    normalized_title = _normalize_required_text(title, MAX_TITLE_LENGTH)
    normalized_device_model = _normalize_optional_text(device_model, MAX_DEVICE_MODEL_LENGTH)
    normalized_firmware_version = _normalize_optional_text(firmware_version, MAX_FIRMWARE_VERSION_LENGTH)
    normalized_symptoms = _normalize_required_text(symptoms, MAX_LONG_TEXT_LENGTH)
    normalized_environment = _normalize_optional_text(environment, MAX_LONG_TEXT_LENGTH)
    normalized_solution = _normalize_required_text(bot_solution, MAX_LONG_TEXT_LENGTH)

    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO field_reports (user_id, title, device_model, firmware_version, symptoms, environment, bot_solution)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                normalized_title,
                normalized_device_model,
                normalized_firmware_version,
                normalized_symptoms,
                normalized_environment,
                normalized_solution,
            ),
        )
        return cursor.lastrowid


def save_bot_message(user_id: int, scan_id: Optional[str], user_message: str, bot_response: str):
    normalized_user_message = _normalize_required_text(user_message, MAX_LONG_TEXT_LENGTH)
    normalized_bot_response = _normalize_required_text(bot_response, MAX_LONG_TEXT_LENGTH)

    with get_connection() as connection:
        connection.execute(
            "INSERT INTO bot_messages (user_id, scan_id, user_message, bot_response) VALUES (?, ?, ?, ?)",
            (user_id, scan_id, normalized_user_message, normalized_bot_response),
        )


def save_scan_record(scan_id: str, user_id: Optional[int], original_filename: str, stored_filename: str):
    normalized_scan_id = _normalize_required_text(scan_id, 36)
    normalized_original_filename = _normalize_required_text(original_filename, 255)
    normalized_stored_filename = _normalize_required_text(stored_filename, 255)

    with get_connection() as connection:
        connection.execute(
            """
            INSERT OR REPLACE INTO scans (scan_id, user_id, original_filename, stored_filename)
            VALUES (?, ?, ?, ?)
            """,
            (normalized_scan_id, user_id, normalized_original_filename, normalized_stored_filename),
        )


def get_scan_record(scan_id: str) -> Optional[dict]:
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT scan_id, user_id, original_filename, stored_filename, created_at
            FROM scans
            WHERE scan_id = ?
            """,
            (_normalize_required_text(scan_id, 36),),
        ).fetchone()

    if row:
        return dict(row)

    return None


def get_recent_bot_messages(user_id: int, limit: int = 8):
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT scan_id, user_message, bot_response, created_at
            FROM bot_messages
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (user_id, limit),
        ).fetchall()

    return [dict(row) for row in rows]


def get_recent_field_reports(user_id: int, limit: int = 5):
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, title, device_model, firmware_version, symptoms, environment, bot_solution, created_at
            FROM field_reports
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (user_id, limit),
        ).fetchall()

    return [dict(row) for row in rows]


def _normalize_required_text(value: str, max_length: int) -> str:
    normalized = (value or "").strip()
    if not normalized:
        raise ValueError("Required text value is missing.")
    return normalized[:max_length]


def _normalize_optional_text(value: str, max_length: int) -> str:
    return (value or "").strip()[:max_length]
