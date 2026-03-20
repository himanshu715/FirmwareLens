from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer


def generate_pdf(result, file_path):
    doc = SimpleDocTemplate(file_path)
    styles = getSampleStyleSheet()
    content = []

    content.append(Paragraph("FirmwareLens Firmware Security Report", styles["Title"]))
    content.append(Spacer(1, 10))
    content.append(Paragraph("Assistant: Sentinel Bot", styles["Normal"]))
    content.append(Spacer(1, 6))

    content.append(Paragraph(f"Scan ID: {result.get('scan_id', 'N/A')}", styles["Normal"]))
    content.append(Paragraph(f"Firmware Type: {result['firmware_type']}", styles["Normal"]))
    content.append(Paragraph(f"Total Strings: {result['total_strings']}", styles["Normal"]))
    content.append(Paragraph(f"Security Score: {result['score']}", styles["Normal"]))
    content.append(
        Paragraph(
            f"Estimated Revenue At Risk: ${result['revenue']['estimated_revenue_at_risk_usd']:,}",
            styles["Normal"],
        )
    )
    content.append(
        Paragraph(
            f"Projected Revenue Protected After Fix: ${result['revenue']['projected_revenue_protected_usd']:,}",
            styles["Normal"],
        )
    )
    content.append(
        Paragraph(f"Incident Likelihood: {result['revenue']['incident_likelihood_percent']}%", styles["Normal"])
    )
    content.append(
        Paragraph(f"Bot: {result.get('ai_agent', {}).get('agent_name', 'Sentinel Bot')}", styles["Normal"])
    )
    content.append(Spacer(1, 10))

    summary = result["summary"]
    content.append(Paragraph("Summary", styles["Heading2"]))
    content.append(Paragraph(f"Critical: {summary['critical']}", styles["Normal"]))
    content.append(Paragraph(f"High: {summary['high']}", styles["Normal"]))
    content.append(Paragraph(f"Medium: {summary['medium']}", styles["Normal"]))
    content.append(Spacer(1, 10))

    breakdown = result.get("breakdown", {})
    content.append(Paragraph("Detection Breakdown", styles["Heading2"]))
    content.append(Paragraph(f"Secrets: {breakdown.get('secrets', 0)}", styles["Normal"]))
    content.append(Paragraph(f"Weak Crypto: {breakdown.get('crypto', 0)}", styles["Normal"]))
    content.append(Paragraph(f"Outdated Libraries: {breakdown.get('libraries', 0)}", styles["Normal"]))
    content.append(Paragraph(f"Suspicious Strings: {breakdown.get('suspicious', 0)}", styles["Normal"]))
    content.append(Paragraph(f"Bad Practices: {breakdown.get('bad_practices', 0)}", styles["Normal"]))
    content.append(Spacer(1, 10))

    ai_agent = result.get("ai_agent", {})
    content.append(Paragraph("Sentinel Bot Guidance", styles["Heading2"]))
    content.append(Paragraph(ai_agent.get("headline", "Bot-guided triage support available."), styles["Normal"]))
    content.append(Paragraph(ai_agent.get("summary", ""), styles["Normal"]))
    content.append(Paragraph(f"Recommended Next Step: {ai_agent.get('recommended_next_step', '')}", styles["Normal"]))
    content.append(Spacer(1, 10))

    content.append(Paragraph("Top Security Issues", styles["Heading2"]))
    content.append(Spacer(1, 5))

    for finding in result["top_findings"]:
        content.append(Paragraph(f"<b>{finding['type']} ({finding['severity']})</b>", styles["Normal"]))
        content.append(Paragraph(f"Evidence: {finding['value']}", styles["Normal"]))
        content.append(Paragraph(f"Description: {finding.get('description', '')}", styles["Normal"]))
        content.append(Paragraph(f"Impact: {finding.get('impact', '')}", styles["Normal"]))
        content.append(Paragraph(f"Revenue Impact: {finding.get('revenue_impact', '')}", styles["Normal"]))
        content.append(Paragraph(f"Estimated Loss: ${finding.get('estimated_loss_usd', 0):,}", styles["Normal"]))
        content.append(Paragraph(f"Fix: {finding.get('recommendation', '')}", styles["Normal"]))
        content.append(Spacer(1, 10))

    content.append(Paragraph("FirmwareLens Notes", styles["Heading2"]))
    content.append(
        Paragraph(
            "This FirmwareLens report includes checks for secrets, weak cryptography, suspicious strings, outdated embedded components, risky implementation patterns, and Sentinel Bot-guided triage support.",
            styles["Normal"],
        )
    )
    content.append(
        Paragraph(
            f"Total surfaced findings: {result.get('all_findings_count', len(result.get('findings', [])))}",
            styles["Normal"],
        )
    )

    doc.build(content)
