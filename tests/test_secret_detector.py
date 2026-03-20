from engine.secret_detector import detect_advanced_secrets


def test_detects_weak_crypto_outdated_libraries_and_bad_practices():
    findings = detect_advanced_secrets(
        [
            "openssl-1.0.2k",
            "use md5 for checksum",
            "debug=true",
            "strcpy(buffer, input)",
        ]
    )

    finding_types = {finding["type"] for finding in findings}

    assert "Outdated Library" in finding_types
    assert "Weak Crypto (MD5)" in finding_types
    assert "Suspicious String" in finding_types
    assert "Bad Practice" in finding_types
