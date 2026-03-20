import os
import shutil
import subprocess


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


def is_valid_string(value):
    return len(value) > 6 and any(char.isalpha() for char in value) and value.isprintable()


def detect_firmware_type(strings):
    if len(strings) < 50:
        return "Likely Encrypted / Packed Firmware"
    if any("linux" in value.lower() for value in strings):
        return "Linux-based Firmware"
    return "Raw Embedded Firmware"


def extract_strings_from_directory(directory):
    all_strings = []

    for root, _dirs, files in os.walk(directory):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            strings = extract_strings(file_path)
            for value in strings:
                if is_valid_string(value) or len(value) > 4:
                    all_strings.append(value)

    return list(set(all_strings))


def find_sensitive_keywords(strings):
    keywords = ["password", "key", "token", "secret"]
    findings = []

    for value in strings:
        for keyword in keywords:
            if keyword in value.lower():
                findings.append(value)
                break

    return findings
