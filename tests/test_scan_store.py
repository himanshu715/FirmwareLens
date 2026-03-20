import uuid

import pytest

from services.scan_store import ScanStorageError, build_upload_path, normalize_scan_id, validate_upload


def test_normalize_scan_id_accepts_uuid_strings():
    raw_scan_id = str(uuid.uuid4())
    assert normalize_scan_id(raw_scan_id) == raw_scan_id


def test_normalize_scan_id_rejects_invalid_ids():
    with pytest.raises(ScanStorageError):
        normalize_scan_id("../bad")


def test_validate_upload_rejects_unsupported_extensions():
    with pytest.raises(ScanStorageError):
        validate_upload("firmware.txt", 10)


def test_build_upload_path_uses_scan_id_and_extension():
    scan_id = str(uuid.uuid4())
    path = build_upload_path(scan_id, "sample.img")
    assert path.name == f"{scan_id}.img"
