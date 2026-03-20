from engine.revenue_model import build_revenue_summary, enrich_findings_with_revenue


def test_enrich_findings_with_revenue_adds_business_fields():
    findings = [
        {
            "type": "AWS Access Key",
            "severity": "CRITICAL",
            "value": "AKIA1234567890ABCDEF12",
            "description": "AWS access key found",
            "impact": "Full access to AWS resources possible",
            "recommendation": "Revoke and rotate immediately",
        }
    ]

    enriched = enrich_findings_with_revenue(findings, "Linux-based Firmware")

    assert enriched[0]["revenue_impact"]
    assert enriched[0]["business_playbook"]
    assert enriched[0]["estimated_loss_usd"] == 216000


def test_build_revenue_summary_returns_enterprise_band_for_large_exposure():
    findings = [
        {
            "severity": "CRITICAL",
            "estimated_loss_usd": 216000,
        },
        {
            "severity": "HIGH",
            "estimated_loss_usd": 66300,
        },
    ]

    summary = build_revenue_summary(findings, "Linux-based Firmware")

    assert summary["estimated_revenue_at_risk_usd"] == 282300
    assert summary["projected_revenue_protected_usd"] == 203256
    assert summary["incident_likelihood_percent"] >= 35
    assert summary["opportunity_band"] == "Enterprise"
    assert "critical exposure" in summary["executive_summary"].lower()
