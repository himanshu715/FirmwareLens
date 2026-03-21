import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
IS_VERCEL = bool(os.getenv("VERCEL", "").strip())
_runtime_root = os.getenv("RUNTIME_ROOT", "").strip()
if _runtime_root:
    runtime_root = Path(_runtime_root).expanduser()
    if not runtime_root.is_absolute():
        runtime_root = (BASE_DIR / _runtime_root).resolve()
else:
    runtime_root = Path("/tmp/firmwarelens") if IS_VERCEL else BASE_DIR

RUNTIME_ROOT = runtime_root
DATA_DIR = RUNTIME_ROOT / "data"
UPLOAD_DIR = RUNTIME_ROOT / "uploads"
EXTRACTED_DIR = RUNTIME_ROOT / "extracted"
RESULTS_DIR = RUNTIME_ROOT / "scan_results"
REPORTS_DIR = RUNTIME_ROOT / "reports"
DB_PATH = DATA_DIR / "sentinel.db"

_default_max_upload_size = 4 * 1024 * 1024 if IS_VERCEL else 50 * 1024 * 1024
try:
    MAX_UPLOAD_SIZE = int(os.getenv("MAX_UPLOAD_SIZE_BYTES", str(_default_max_upload_size)))
except ValueError:
    MAX_UPLOAD_SIZE = _default_max_upload_size
MAX_UPLOAD_SIZE_MB = round(MAX_UPLOAD_SIZE / 1024 / 1024, 1)
ALLOWED_EXTENSIONS = {".bin", ".img", ".fw", ".hex", ".elf"}
SITE_URL = os.getenv("SITE_URL", "").strip().rstrip("/")
ADS_TXT_CONTENT = os.getenv("ADS_TXT_CONTENT", "").strip()
PREFERRED_URL_SCHEME = "https" if SITE_URL.startswith("https://") else "http"
_default_backend_public_url = "https://firmwarelens.onrender.com" if IS_VERCEL else ""
BACKEND_PUBLIC_URL = os.getenv("BACKEND_PUBLIC_URL", _default_backend_public_url).strip().rstrip("/")
_default_frontend_public_url = "https://firmware-lens.vercel.app" if not IS_VERCEL else (SITE_URL or "")
FRONTEND_PUBLIC_URL = os.getenv("FRONTEND_PUBLIC_URL", _default_frontend_public_url).strip().rstrip("/")
PUBLIC_ANALYZE_URL = f"{BACKEND_PUBLIC_URL}/public/analyze" if BACKEND_PUBLIC_URL else ""
_default_public_scan_size = 50 * 1024 * 1024 if PUBLIC_ANALYZE_URL else MAX_UPLOAD_SIZE
try:
    PUBLIC_SCAN_MAX_UPLOAD_SIZE = int(
        os.getenv("PUBLIC_SCAN_MAX_UPLOAD_SIZE_BYTES", str(_default_public_scan_size))
    )
except ValueError:
    PUBLIC_SCAN_MAX_UPLOAD_SIZE = _default_public_scan_size
PUBLIC_SCAN_MAX_UPLOAD_SIZE_MB = round(PUBLIC_SCAN_MAX_UPLOAD_SIZE / 1024 / 1024, 1)
API_ALLOWED_ORIGINS = tuple(
    origin
    for origin in dict.fromkeys([SITE_URL, FRONTEND_PUBLIC_URL, BACKEND_PUBLIC_URL])
    if origin
)
DEPLOYMENT_NOTICE = (
    (
        "This Vercel deployment runs in preview mode, but firmware uploads can be routed directly "
        "to the persistent Render backend when backend upload is enabled."
        if PUBLIC_ANALYZE_URL
        else "This Vercel deployment runs in preview mode with temporary storage and stricter upload limits. "
        "Use Render or another persistent host for the full FirmwareLens workflow."
    )
    if IS_VERCEL
    else ""
)


def ensure_runtime_dirs():
    for directory in (DATA_DIR, UPLOAD_DIR, EXTRACTED_DIR, RESULTS_DIR, REPORTS_DIR):
        directory.mkdir(parents=True, exist_ok=True)


def public_origin(request=None):
    if SITE_URL:
        return SITE_URL
    if request is None:
        return ""
    return request.url_root.rstrip("/")


def build_content_security_policy(enable_analytics=False):
    directives = {
        "default-src": ["'self'"],
        "style-src": ["'self'", "'unsafe-inline'"],
        "script-src": ["'self'", "'unsafe-inline'"],
        "img-src": ["'self'", "data:"],
        "connect-src": ["'self'"],
        "font-src": ["'self'", "data:"],
        "form-action": ["'self'"],
        "base-uri": ["'self'"],
        "frame-ancestors": ["'self'"],
        "object-src": ["'none'"],
    }

    if enable_analytics:
        directives["script-src"].append("https://www.googletagmanager.com")
        directives["img-src"].extend(
            [
                "https://www.google-analytics.com",
                "https://www.googletagmanager.com",
            ]
        )
        directives["connect-src"].extend(
            [
                "https://www.google-analytics.com",
                "https://region1.google-analytics.com",
                "https://www.googletagmanager.com",
            ]
        )

    if BACKEND_PUBLIC_URL:
        directives["form-action"].append(BACKEND_PUBLIC_URL)
        directives["connect-src"].append(BACKEND_PUBLIC_URL)

    return "; ".join(
        f"{directive} {' '.join(sources)}" for directive, sources in directives.items()
    )
