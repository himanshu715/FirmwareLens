from __future__ import annotations

from typing import Dict, List


SEVERITY_WEIGHTS = {
    "CRITICAL": 1.0,
    "HIGH": 0.65,
    "MEDIUM": 0.35,
    "LOW": 0.15,
}


FINDING_PROFILES = {
    "AWS Access Key": {
        "base_loss": 180000,
        "label": "Cloud service abuse and customer trust erosion",
        "playbook": "Rotate exposed cloud credentials, audit usage, and re-issue scoped IAM keys.",
    },
    "Private Key": {
        "base_loss": 250000,
        "label": "Firmware signing compromise and product-wide recall pressure",
        "playbook": "Replace signing material, rotate certificates, and verify secure key custody.",
    },
    "Hardcoded Password": {
        "base_loss": 85000,
        "label": "Unauthorized access leading to churn and service remediation spend",
        "playbook": "Remove static credentials and enforce device-unique secrets.",
    },
    "API Key": {
        "base_loss": 95000,
        "label": "Abuse of paid APIs and downstream service interruption",
        "playbook": "Move keys to protected storage and rotate compromised tokens.",
    },
    "JWT Token": {
        "base_loss": 70000,
        "label": "Session takeover and unauthorized account actions",
        "playbook": "Invalidate leaked tokens and shorten token lifetime.",
    },
    "Credential Leak in URL": {
        "base_loss": 65000,
        "label": "Credential harvesting via logs, proxies, and browser history",
        "playbook": "Strip credentials from URLs and rotate impacted accounts.",
    },
    "Encoded Secret": {
        "base_loss": 30000,
        "label": "Potential sensitive data disclosure requiring manual triage",
        "playbook": "Decode the value and verify whether it unlocks production systems.",
    },
    "Possible API Key": {
        "base_loss": 22000,
        "label": "Potential monetizable abuse if the token is valid",
        "playbook": "Validate the secret and remove it from distributed firmware.",
    },
}


FIRMWARE_MULTIPLIERS = {
    "Linux-based Firmware": 1.2,
    "Raw Embedded Firmware": 1.0,
    "Likely Encrypted / Packed Firmware": 0.8,
}


def enrich_findings_with_revenue(findings: List[Dict], firmware_type: str) -> List[Dict]:
    multiplier = FIRMWARE_MULTIPLIERS.get(firmware_type, 1.0)
    enriched = []

    for finding in findings:
        profile = FINDING_PROFILES.get(
            finding["type"],
            {
                "base_loss": 20000,
                "label": "Operational disruption and trust impact",
                "playbook": "Investigate the exposure and contain it before release.",
            },
        )
        severity_weight = SEVERITY_WEIGHTS.get(finding["severity"], 0.2)
        estimated_loss = int(profile["base_loss"] * severity_weight * multiplier)

        enriched_finding = dict(finding)
        enriched_finding["revenue_impact"] = profile["label"]
        enriched_finding["estimated_loss_usd"] = estimated_loss
        enriched_finding["business_playbook"] = profile["playbook"]
        enriched.append(enriched_finding)

    return enriched


def build_revenue_summary(findings: List[Dict], firmware_type: str) -> Dict:
    revenue_at_risk = sum(f["estimated_loss_usd"] for f in findings)
    critical_count = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high_count = sum(1 for f in findings if f["severity"] == "HIGH")
    multiplier = FIRMWARE_MULTIPLIERS.get(firmware_type, 1.0)

    opportunity_band = "Pilot"
    if revenue_at_risk >= 250000:
        opportunity_band = "Enterprise"
    elif revenue_at_risk >= 100000:
        opportunity_band = "Growth"

    likelihood = min(92, int((critical_count * 18 + high_count * 10 + len(findings) * 2) * multiplier))
    protected_revenue = int(revenue_at_risk * 0.72)

    return {
        "estimated_revenue_at_risk_usd": revenue_at_risk,
        "projected_revenue_protected_usd": protected_revenue,
        "incident_likelihood_percent": max(likelihood, 8 if findings else 3),
        "opportunity_band": opportunity_band,
        "executive_summary": _build_executive_summary(revenue_at_risk, critical_count, high_count),
    }


def _build_executive_summary(revenue_at_risk: int, critical_count: int, high_count: int) -> str:
    if revenue_at_risk == 0:
        return "No immediate revenue-linked exposures were detected in this firmware sample."
    if critical_count:
        return (
            f"{critical_count} critical exposure(s) put release revenue and downstream service trust at material risk."
        )
    if high_count:
        return (
            f"High-severity exposures could convert into preventable support cost, churn, and SLA penalties."
        )
    return "Medium-severity findings suggest moderate business leakage risk that should be fixed before scale-out."
