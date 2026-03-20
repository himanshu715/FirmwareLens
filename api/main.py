import os

from fastapi import FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from api.pdf_report import generate_pdf
from api.upload_api import router as upload_router
from config import BASE_DIR, build_content_security_policy, ensure_runtime_dirs
from engine.analyzer import analyze_firmware
from services.app_db import init_db, save_scan_record
from services.scan_store import (
    ScanStorageError,
    build_report_path,
    build_upload_path,
    create_scan_id,
    load_result,
    persist_result,
    validate_upload,
)


ensure_runtime_dirs()
init_db()

app = FastAPI(title="FirmwareLens Firmware Security Analyzer API")
app.include_router(upload_router)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
API_ACCESS_KEY = os.getenv("API_ACCESS_KEY", "").strip()
GA_MEASUREMENT_ID = os.getenv("GA_MEASUREMENT_ID", "").strip()


def require_api_key(x_api_key: str | None):
    if API_ACCESS_KEY and x_api_key != API_ACCESS_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key.")


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = build_content_security_policy(
        enable_analytics=bool(GA_MEASUREMENT_ID)
    )
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=604800, immutable"
    else:
        response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/health")
def health():
    return {"status": "ok", "app": "firmwarelens-api"}


@app.post("/analyze")
async def analyze(request: Request, firmware: UploadFile = File(...), x_api_key: str | None = Header(default=None)):
    require_api_key(x_api_key)
    payload = await firmware.read()

    try:
        validate_upload(firmware.filename, len(payload))
    except ScanStorageError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    scan_id = create_scan_id()
    file_path = build_upload_path(scan_id, firmware.filename)
    file_path.write_bytes(payload)
    save_scan_record(scan_id, None, firmware.filename, file_path.name)

    result = analyze_firmware(str(file_path))
    result["scan_id"] = scan_id
    persist_result(scan_id, result)

    return templates.TemplateResponse(
        "result.html",
        {
            "request": request,
            "result": result,
            "user": {"username": "api-user"},
            "app_mode": "api",
            "ga_measurement_id": GA_MEASUREMENT_ID,
            "analytics_events": [],
        },
    )


@app.get("/analyze-json/{scan_id}")
def analyze_json(scan_id: str, x_api_key: str | None = Header(default=None)):
    require_api_key(x_api_key)
    try:
        result = load_result(scan_id)
    except ScanStorageError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return result


@app.get("/download-report")
def download_report(scan_id: str, x_api_key: str | None = Header(default=None)):
    require_api_key(x_api_key)
    try:
        result = load_result(scan_id)
    except ScanStorageError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found.")

    file_path = build_report_path(scan_id)
    generate_pdf(result, str(file_path))

    return FileResponse(path=file_path, filename=f"firmware_report_{scan_id}.pdf", media_type="application/pdf")
