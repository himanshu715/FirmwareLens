import shutil
import subprocess
import uuid
from pathlib import Path

from config import EXTRACTED_DIR, ensure_runtime_dirs


ensure_runtime_dirs()


def extract_firmware(file_path):
    if shutil.which("binwalk") is None:
        return None

    scan_id = str(uuid.uuid4())
    output_dir = EXTRACTED_DIR / scan_id
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        result = subprocess.run(
            ["binwalk", "-e", file_path, "-C", str(output_dir)],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    if result.returncode != 0:
        return None

    extracted_files = list(Path(output_dir).rglob("*"))
    if not any(path.is_file() for path in extracted_files):
        return None

    return str(output_dir)
