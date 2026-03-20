import os
import shutil
import subprocess


SENSITIVE_KEYWORDS = ("password", "key", "token", "secret")


def extract_strings(file_path):
    if shutil.which("strings") is None:
        return []

    try:
        result = subprocess.run(
            ["strings", file_path],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return []

    if result.returncode != 0:
        return []

    return result.stdout.splitlines()

def detect_firmware_type(strings):
    if len(strings) < 50:
        return "Likely Encrypted / Packed Firmware"
    if any("linux" in value.lower() for value in strings):
        return "Linux-based Firmware"
    return "Raw Embedded Firmware"


def extract_strings_from_directory(directory):
    unique_strings = set()

    for root, _dirs, files in os.walk(directory):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            for value in extract_strings(file_path):
                if _should_keep_extracted_string(value):
                    unique_strings.add(value)

    return list(unique_strings)


def find_sensitive_keywords(strings):
    findings = []

    for value in strings:
        lowered = value.lower()
        if any(keyword in lowered for keyword in SENSITIVE_KEYWORDS):
            findings.append(value)

    return findings


def _should_keep_extracted_string(value):
    return len(value) > 4 and value.isprintable()
