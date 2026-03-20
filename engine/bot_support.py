def build_chat_reply(message, scan_result=None):
    normalized = message.strip().lower()
    scan_result = scan_result or {}
    breakdown = scan_result.get("breakdown", {})
    top_findings = scan_result.get("top_findings", [])

    if not normalized:
        return "Please ask a question about your firmware findings, field issue, or troubleshooting scenario."

    if any(keyword in normalized for keyword in ["secret", "credential", "password", "token", "key"]):
        return _format_reply(
            "Credential exposure guidance",
            [
                "Rotate any exposed credentials before your next firmware release.",
                "Check the report's secrets breakdown and prioritize CRITICAL or HIGH findings first.",
                "Remove hardcoded secrets from firmware images and move them to secure provisioning or device-unique storage.",
            ],
            top_findings,
        )

    if any(keyword in normalized for keyword in ["crypto", "tls", "ssl", "certificate", "cert", "handshake"]):
        return _format_reply(
            "Crypto and connectivity guidance",
            [
                "Review weak cryptography hits and replace deprecated algorithms such as MD5, SHA1, DES, 3DES, and RC4.",
                "If field devices cannot connect, verify certificate validity, system time, and CA bundle freshness.",
                "Map any outdated library version strings to your firmware bill of materials and patch supported versions.",
            ],
            top_findings,
        )

    if any(keyword in normalized for keyword in ["crash", "reboot", "watchdog", "hang", "freeze"]):
        return _format_reply(
            "Field stability guidance",
            [
                "Correlate crash timing with risky implementation patterns such as unsafe string handling or permissive update paths.",
                "Capture watchdog resets, uptime, last successful action, and any recent config changes from the field unit.",
                "If a debugger is unavailable, reproduce with verbose logs, safe-mode settings, and a controlled firmware rollback plan.",
            ],
            top_findings,
        )

    if any(keyword in normalized for keyword in ["update", "ota", "boot", "rollback", "signing"]):
        return _format_reply(
            "Boot and update guidance",
            [
                "Verify signature checks, rollback logic, and bootloader compatibility across the affected firmware build.",
                "Review suspicious strings and bad-practice detections for skipped verification or unsafe update behavior.",
                "Ask field teams to capture update timestamps, power events, and device model identifiers before reattempting.",
            ],
            top_findings,
        )

    if any(keyword in normalized for keyword in ["memory", "heap", "stack", "leak", "overflow"]):
        return _format_reply(
            "Memory and stability guidance",
            [
                "Inspect bad-practice findings for unsafe string or buffer operations that can cause corruption in field deployments.",
                "Without a debugger, collect memory usage counters, reset counts, and the last successful workflow from device logs.",
                "If the issue appears progressive over time, compare firmware uptime and feature usage to isolate leak-like behavior.",
            ],
            top_findings,
        )

    summary_line = "The scan does not point to one obvious root cause from your question alone."
    if breakdown:
        summary_line = (
            f"Current scan emphasis: secrets={breakdown.get('secrets', 0)}, "
            f"crypto={breakdown.get('crypto', 0)}, libraries={breakdown.get('libraries', 0)}, "
            f"suspicious={breakdown.get('suspicious', 0)}, bad_practices={breakdown.get('bad_practices', 0)}."
        )

    return (
        f"{summary_line} Start by matching the field symptom to the top findings, capture device model and firmware version, "
        "and use the field issue report form if you need a structured bot-generated solution."
    )


def build_field_issue_solution(title, device_model, firmware_version, symptoms, environment):
    combined = " ".join([title, device_model, firmware_version, symptoms, environment]).lower()

    probable_causes = []
    actions = []

    if any(keyword in combined for keyword in ["reboot", "watchdog", "hang", "freeze", "crash"]):
        probable_causes.append("Runtime instability, watchdog resets, or unsafe low-level operations.")
        actions.append("Collect reset reason, uptime before reboot, and the last successful action from field logs.")
        actions.append("Compare the issue against bad-practice findings such as unsafe string handling or shell execution paths.")

    if any(keyword in combined for keyword in ["network", "tls", "ssl", "cert", "connect", "mqtt", "http"]):
        probable_causes.append("Connectivity, certificate validation, or outdated crypto/library behavior.")
        actions.append("Verify device time, certificate chain, CA bundle, and server reachability from the field environment.")
        actions.append("Check for weak crypto or outdated library findings that might explain interoperability failures.")

    if any(keyword in combined for keyword in ["update", "ota", "boot", "rollback"]):
        probable_causes.append("Firmware update validation or boot compatibility problems.")
        actions.append("Capture boot logs, update package version, and whether rollback protection or signature checks were triggered.")
        actions.append("Verify image compatibility for the device model and bootloader path used in the field.")

    if any(keyword in combined for keyword in ["memory", "heap", "stack", "leak", "overflow"]):
        probable_causes.append("Memory pressure, leak-like accumulation, or buffer misuse.")
        actions.append("Record memory usage over time, uptime at failure, and workload pattern before the issue occurs.")
        actions.append("Review bad-practice findings and high-risk parser or protocol paths in this firmware branch.")

    if not probable_causes:
        probable_causes.append("Configuration mismatch, environment-specific failure, or firmware regression.")
        actions.append("Capture exact reproduction steps, device model, firmware version, logs, and recent changes in the field environment.")
        actions.append("Use bot chat with the scan findings and issue description to narrow the likely subsystem.")

    actions.append("If no debugger is available, prioritize remote logs, staged rollback, configuration diffing, and a reproducible lab simulation.")

    return (
        "Probable causes: "
        + " ".join(probable_causes)
        + " Recommended field actions: "
        + " ".join(actions)
    )


def _format_reply(title, bullets, top_findings):
    finding_hint = ""
    if top_findings:
        finding_hint = f" Top findings currently include {', '.join(finding.get('type', '') for finding in top_findings[:3])}."

    return f"{title}: " + " ".join(bullets) + finding_hint
