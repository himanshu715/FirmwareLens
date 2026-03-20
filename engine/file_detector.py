import shutil
import subprocess


def detect_file_type(file_path):
    with open(file_path, "rb") as file_handle:
        header = file_handle.read(10)

    if header.startswith(b"\x7fELF"):
        return "ELF"
    if header.startswith(b":"):
        return "HEX"
    return "BIN"


def detect_architecture(file_path):
    if shutil.which("file") is None:
        return "Unknown"

    try:
        result = subprocess.run(
            ["file", file_path],
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError):
        return "Unknown"

    return result.stdout.strip() if result.returncode == 0 and result.stdout.strip() else "Unknown"


def get_firmware_info(file_path):
    return {"file_type": detect_file_type(file_path), "architecture": detect_architecture(file_path)}
