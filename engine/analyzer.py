from engine.ai_agent import build_ai_agent_support
from engine.extractor import extract_firmware
from engine.file_detector import get_firmware_info
from engine.revenue_model import build_revenue_summary, enrich_findings_with_revenue
from engine.secret_detector import detect_all_findings
from engine.string_analyzer import (
    detect_firmware_type,
    extract_strings,
    extract_strings_from_directory,
    find_sensitive_keywords,
)


SEVERITY_PRIORITY = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}

SCORE_PENALTIES = {
    "Private Key": 50,
    "AWS Access Key": 45,
    "Hardcoded Password": 30,
    "API Key": 20,
    "Credential Leak in URL": 15,
    "Weak Crypto (MD5)": 15,
    "Weak Crypto (DES)": 15,
    "Weak Crypto (RC4)": 15,
    "Weak Crypto (SHA1)": 10,
    "Weak Crypto (3DES)": 10,
    "Outdated Library": 12,
    "Suspicious String": 10,
    "Bad Practice": 12,
    "Possible API Key": 5,
    "Encoded Secret": 5,
}

FREE_TIER = {
    "label": "Free",
    "price_inr": 0,
    "finding_limit": None,
    "show_pdf": True,
    "depth": "Full scan",
}

SECRET_FINDING_TYPES = frozenset(
    {
        "Hardcoded Password",
        "API Key",
        "JWT Token",
        "AWS Access Key",
        "Private Key",
        "Possible API Key",
        "Encoded Secret",
        "Credential Leak in URL",
    }
)


def calculate_score(findings):
    return max(100 - sum(SCORE_PENALTIES.get(finding["type"], 3) for finding in findings), 0)


def analyze_firmware(file_path, scan_tier="free"):
    firmware_info = get_firmware_info(file_path)
    extracted_path = extract_firmware(file_path)

    if extracted_path:
        strings = extract_strings_from_directory(extracted_path)
    else:
        strings = extract_strings(file_path)

    firmware_type = detect_firmware_type(strings)
    sensitive = find_sensitive_keywords(strings)

    all_findings = _deduplicate_findings(detect_all_findings(strings))
    all_findings = enrich_findings_with_revenue(all_findings, firmware_type)
    all_findings = sorted(
        all_findings,
        key=lambda finding: (
            SEVERITY_PRIORITY.get(finding["severity"], 0),
            finding.get("estimated_loss_usd", 0),
        ),
        reverse=True,
    )

    summary, breakdown = _build_summary_and_breakdown(all_findings)

    result = {
        "firmware_type": firmware_type,
        "total_strings": len(strings),
        "top_findings": all_findings[:5],
        "findings": all_findings,
        "summary": summary,
        "firmware_info": firmware_info,
        "sample_strings": strings[:20],
        "sensitive_strings": sensitive[:20],
        "score": calculate_score(all_findings),
        "revenue": build_revenue_summary(all_findings, firmware_type),
        "breakdown": breakdown,
        "issues": [],
        "scan_tier": "free",
        "tier": FREE_TIER,
        "all_findings_count": len(all_findings),
        "hidden_findings_count": 0,
    }

    result["ai_agent"] = build_ai_agent_support(result)
    return result


def _deduplicate_findings(findings):
    unique_findings = []
    seen = set()

    for finding in findings:
        identity = (finding.get("type"), finding.get("value"))
        if identity in seen:
            continue
        seen.add(identity)
        unique_findings.append(finding)

    return unique_findings


def _build_summary_and_breakdown(findings):
    summary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
    }
    buckets = {
        "secrets": 0,
        "crypto": 0,
        "libraries": 0,
        "suspicious": 0,
        "bad_practices": 0,
    }

    for finding in findings:
        finding_type = finding.get("type", "")
        severity = finding.get("severity")

        if severity == "CRITICAL":
            summary["critical"] += 1
        elif severity == "HIGH":
            summary["high"] += 1
        elif severity == "MEDIUM":
            summary["medium"] += 1

        if finding_type in SECRET_FINDING_TYPES:
            buckets["secrets"] += 1
        elif finding_type.startswith("Weak Crypto"):
            buckets["crypto"] += 1
        elif finding_type == "Outdated Library":
            buckets["libraries"] += 1
        elif finding_type == "Suspicious String":
            buckets["suspicious"] += 1
        elif finding_type == "Bad Practice":
            buckets["bad_practices"] += 1

    return summary, buckets
