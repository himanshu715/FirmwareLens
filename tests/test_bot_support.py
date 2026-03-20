from engine.bot_support import build_chat_reply, build_field_issue_solution


def test_build_chat_reply_handles_secret_question():
    reply = build_chat_reply(
        "How should I handle exposed credentials?",
        {
            "breakdown": {"secrets": 2, "crypto": 0, "libraries": 0, "suspicious": 0, "bad_practices": 0},
            "top_findings": [{"type": "Hardcoded Password"}, {"type": "API Key"}],
        },
    )

    assert "Rotate any exposed credentials" in reply
    assert "Hardcoded Password" in reply


def test_build_field_issue_solution_handles_reboot_reports():
    solution = build_field_issue_solution(
        "Gateway keeps rebooting",
        "STM32 gateway",
        "1.2.7",
        "Device reboots every 10 minutes in the field",
        "No debugger available, remote logs only",
    )

    assert "watchdog" in solution.lower() or "runtime instability" in solution.lower()
    assert "Collect reset reason" in solution
