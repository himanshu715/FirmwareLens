import os

from fastapi import APIRouter, File, Header, HTTPException, UploadFile

from services.app_db import init_db, save_scan_record
from services.scan_store import ScanStorageError, build_upload_path, create_scan_id, validate_upload


router = APIRouter()
init_db()
API_ACCESS_KEY = os.getenv("API_ACCESS_KEY", "").strip()


def require_api_key(x_api_key: str | None):
    if API_ACCESS_KEY and x_api_key != API_ACCESS_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key.")


@router.post("/upload")
async def upload_firmware(file: UploadFile = File(...), x_api_key: str | None = Header(default=None)):
    require_api_key(x_api_key)
    payload = await file.read()

    try:
        validate_upload(file.filename, len(payload))
    except ScanStorageError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    scan_id = create_scan_id()
    file_path = build_upload_path(scan_id, file.filename)
    file_path.write_bytes(payload)
    save_scan_record(scan_id, None, file.filename, file_path.name)

    return {
        "scan_id": scan_id,
        "filename": file_path.name,
        "message": "Firmware uploaded successfully",
    }
