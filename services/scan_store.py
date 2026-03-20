import json
import uuid
from pathlib import Path

from werkzeug.utils import secure_filename

from config import ALLOWED_EXTENSIONS, MAX_UPLOAD_SIZE, REPORTS_DIR, RESULTS_DIR, UPLOAD_DIR, ensure_runtime_dirs


ensure_runtime_dirs()


class ScanStorageError(ValueError):
    pass


def create_scan_id():
    return str(uuid.uuid4())


def normalize_scan_id(scan_id):
    try:
        return str(uuid.UUID(str(scan_id)))
    except (ValueError, TypeError) as error:
        raise ScanStorageError("Invalid scan identifier.") from error


def validate_upload(filename, size):
    if not filename:
        raise ScanStorageError("No firmware file was provided.")

    extension = Path(filename).suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
        raise ScanStorageError("Unsupported firmware format.")

    if size > MAX_UPLOAD_SIZE:
        raise ScanStorageError("File too large.")


def build_upload_path(scan_id, original_filename):
    sanitized = secure_filename(original_filename) or "firmware.bin"
    extension = Path(sanitized).suffix.lower()
    return UPLOAD_DIR / f"{scan_id}{extension}"


def persist_result(scan_id, result):
    normalized_scan_id = normalize_scan_id(scan_id)
    result_path = RESULTS_DIR / f"{normalized_scan_id}.json"
    with result_path.open("w", encoding="utf-8") as handle:
        json.dump(result, handle, ensure_ascii=True, indent=2)
    return result_path


def load_result(scan_id):
    normalized_scan_id = normalize_scan_id(scan_id)
    result_path = RESULTS_DIR / f"{normalized_scan_id}.json"
    if not result_path.exists():
        return None
    with result_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def build_report_path(scan_id):
    normalized_scan_id = normalize_scan_id(scan_id)
    return REPORTS_DIR / f"{normalized_scan_id}.pdf"
