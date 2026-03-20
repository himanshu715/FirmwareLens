from engine.secret_detector import detect_advanced_secrets, detect_all_findings


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


def test_detect_all_findings_combines_basic_and_advanced_checks():
    findings = detect_all_findings(
        [
            "password=admin123",
            "api_key=service-token",
            "use md5 for checksum",
        ]
    )

    finding_types = {finding["type"] for finding in findings}

    assert "Hardcoded Password" in finding_types
    assert "API Key" in finding_types
    assert "Weak Crypto (MD5)" in finding_types
