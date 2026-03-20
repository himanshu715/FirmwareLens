from engine import analyzer


def test_analyze_firmware_returns_full_free_result(monkeypatch):
    monkeypatch.setattr(analyzer, "get_firmware_info", lambda _: {"file_type": "BIN", "architecture": "ARM"})
    monkeypatch.setattr(analyzer, "extract_firmware", lambda _: None)
    monkeypatch.setattr(
        analyzer,
        "extract_strings",
        lambda _: [
            "password=admin123",
            "api_key=super-secret-key",
            "AKIA1234567890ABCDEF",
            "https://admin:secret@example.com",
        ],
    )

    result = analyzer.analyze_firmware("fake.bin")

    assert result["firmware_type"] == "Likely Encrypted / Packed Firmware"
    assert result["firmware_info"]["file_type"] == "BIN"
    assert "revenue" in result
    assert result["revenue"]["estimated_revenue_at_risk_usd"] > 0
    assert result["top_findings"][0]["severity"] == "CRITICAL"
    assert "estimated_loss_usd" in result["top_findings"][0]
    assert "revenue_impact" in result["top_findings"][0]
    assert result["scan_tier"] == "free"
    assert result["tier"]["show_pdf"] is True
    assert result["hidden_findings_count"] == 0
    assert "breakdown" in result
    assert result["ai_agent"]["agent_name"] == "Sentinel Bot"
    assert result["ai_agent"]["priority_actions"]


def test_analyze_firmware_deduplicates_same_type_and_value(monkeypatch):
    monkeypatch.setattr(analyzer, "get_firmware_info", lambda _: {"file_type": "BIN", "architecture": "Unknown"})
    monkeypatch.setattr(analyzer, "extract_firmware", lambda _: None)
    monkeypatch.setattr(analyzer, "extract_strings", lambda _: ["password=admin123"])

    duplicate_findings = [
        {
            "type": "Hardcoded Password",
            "value": "password=admin123",
            "severity": "HIGH",
            "description": "Hardcoded credentials found inside firmware",
            "impact": "Attackers can extract credentials and gain unauthorized access",
            "recommendation": "Remove hardcoded credentials and use secure storage",
        },
        {
            "type": "Hardcoded Password",
            "value": "password=admin123",
            "severity": "HIGH",
            "description": "Hardcoded credentials found inside firmware",
            "impact": "Attackers can extract credentials and gain unauthorized access",
            "recommendation": "Remove hardcoded credentials and use secure storage",
        },
    ]

    monkeypatch.setattr(analyzer, "detect_all_findings", lambda _: duplicate_findings)

    result = analyzer.analyze_firmware("fake.bin")

    assert len(result["findings"]) == 1
    assert result["summary"]["high"] == 1


def test_full_free_scan_exposes_all_findings(monkeypatch):
    monkeypatch.setattr(analyzer, "get_firmware_info", lambda _: {"file_type": "BIN", "architecture": "ARM"})
    monkeypatch.setattr(analyzer, "extract_firmware", lambda _: None)
    monkeypatch.setattr(analyzer, "extract_strings", lambda _: ["password=admin123"])
    monkeypatch.setattr(
        analyzer,
        "detect_all_findings",
        lambda _: [
            {
                "type": "Hardcoded Password",
                "value": f"password=admin{i}",
                "severity": "HIGH",
                "description": "Hardcoded credentials found inside firmware",
                "impact": "Attackers can extract credentials and gain unauthorized access",
                "recommendation": "Remove hardcoded credentials and use secure storage",
            }
            for i in range(8)
        ],
    )

    result = analyzer.analyze_firmware("fake.bin")

    assert len(result["findings"]) == 8
    assert result["all_findings_count"] == 8
    assert result["hidden_findings_count"] == 0
    assert "free full report" in result["ai_agent"]["recommended_next_step"].lower()


def test_breakdown_counts_detection_families(monkeypatch):
    monkeypatch.setattr(analyzer, "get_firmware_info", lambda _: {"file_type": "BIN", "architecture": "ARM"})
    monkeypatch.setattr(analyzer, "extract_firmware", lambda _: None)
    monkeypatch.setattr(analyzer, "extract_strings", lambda _: ["dummy"])
    monkeypatch.setattr(
        analyzer,
        "detect_all_findings",
        lambda _: [
            {
                "type": "Outdated Library",
                "value": "openssl-1.0.2",
                "severity": "HIGH",
                "description": "",
                "impact": "",
                "recommendation": "",
            },
            {
                "type": "Weak Crypto (MD5)",
                "value": "md5",
                "severity": "HIGH",
                "description": "",
                "impact": "",
                "recommendation": "",
            },
            {
                "type": "Suspicious String",
                "value": "debug=true",
                "severity": "MEDIUM",
                "description": "",
                "impact": "",
                "recommendation": "",
            },
            {
                "type": "Bad Practice",
                "value": "strcpy(buffer, src)",
                "severity": "HIGH",
                "description": "",
                "impact": "",
                "recommendation": "",
            },
        ],
    )

    result = analyzer.analyze_firmware("fake.bin")

    assert result["breakdown"]["libraries"] == 1
    assert result["breakdown"]["crypto"] == 1
    assert result["breakdown"]["suspicious"] == 1
    assert result["breakdown"]["bad_practices"] == 1
