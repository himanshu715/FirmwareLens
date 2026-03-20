def build_ai_agent_support(result):
    findings = result.get("top_findings", [])
    top_types = [finding.get("type", "") for finding in findings[:3]]
    revenue = result.get("revenue", {})
    breakdown = result.get("breakdown", {})
    priority_actions = []

    if any(finding.get("severity") == "CRITICAL" for finding in findings):
        priority_actions.append("Contain exposed critical secrets first, especially keys and private credentials.")
    if breakdown.get("crypto"):
        priority_actions.append("Review weak cryptography usage and replace deprecated algorithms before release.")
    if breakdown.get("libraries"):
        priority_actions.append("Map outdated component strings to actual package inventory and patch supported versions.")
    if breakdown.get("bad_practices"):
        priority_actions.append("Audit unsafe implementation patterns like strcpy, gets, and permissive file handling.")
    if breakdown.get("suspicious"):
        priority_actions.append("Manually review suspicious debug or bypass markers for unintended production behavior.")

    if not priority_actions:
        priority_actions.append("No urgent AI-guided action was generated because the scan surfaced limited findings.")

    if revenue.get("estimated_revenue_at_risk_usd", 0) >= 250000:
        stance = "Escalate this firmware build for release-blocking review."
    elif revenue.get("estimated_revenue_at_risk_usd", 0) >= 100000:
        stance = "Treat this scan as a high-priority remediation sprint."
    else:
        stance = "Address findings during the current hardening cycle and re-scan before shipping."

    next_step = "Use the free full report as the handoff artifact for engineering, QA, security review, and release planning."

    return {
        "agent_name": "Sentinel Bot",
        "status": "Active",
        "headline": "Sentinel Bot is triaging the highest-impact firmware risks for you.",
        "summary": _build_summary(top_types, stance),
        "priority_actions": priority_actions[:4],
        "recommended_next_step": next_step,
        "triage_stance": stance,
    }


def _build_summary(top_types, stance):
    if top_types:
        joined = ", ".join(item for item in top_types if item)
        return f"Primary risk themes detected: {joined}. {stance}"
    return f"No dominant risk theme was detected. {stance}"
