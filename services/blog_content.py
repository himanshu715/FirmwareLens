from math import ceil


BLOG_INDEX_COPY = {
    "title": "Firmware Debugging, RTOS, and Embedded Troubleshooting Guides",
    "description": (
        "Read practical guides on firmware debugging, watchdog resets, UART/SPI/I2C issues, "
        "RTOS troubleshooting, and common embedded bugs, with clear workflows teams can apply fast."
    ),
}


RAW_BLOG_POSTS = [
    {
        "slug": "firmware-debugging-guide",
        "title": "Firmware Debugging Guide: A Practical Workflow For Embedded Teams",
        "description": (
            "A practical firmware debugging guide covering repeatability, binary inspection, "
            "instrumentation, and fast triage for embedded failures."
        ),
        "published_at": "2026-03-27",
        "updated_at": "2026-03-27",
        "category": "Debugging",
        "search_terms": [
            "firmware debugging tool online",
            "embedded firmware troubleshooting",
            "firmware bug analysis",
        ],
        "intro": (
            "Firmware bugs feel slow because the failure usually hides behind timing, hardware state, "
            "or a partial boot path. A better workflow is to make the failure measurable, shrink the "
            "possible causes, and collect enough evidence that every new test teaches you something."
        ),
        "takeaways": [
            "Start by naming the failure precisely: boot loop, watchdog reset, protocol timeout, brownout, or data corruption.",
            "Use binary inspection and logs early, even before you reproduce the issue on a bench.",
            "Treat each experiment as a filter that removes classes of causes instead of random trial and error.",
            "Capture fixes as a checklist so the same issue becomes easier to diagnose next time.",
        ],
        "sections": [
            {
                "heading": "1. Define The Failure Signature Before Touching Code",
                "paragraphs": [
                    "The fastest teams do not start with a debugger window. They start with a clean symptom statement that includes trigger conditions, affected hardware revisions, firmware version, power state, and what the device does immediately before failure. That turns a vague complaint into a searchable engineering problem.",
                    "A failure signature should answer simple questions: does the reset happen during boot, after a command, after network traffic, or only after long uptime? Is there a visible LED pattern, a log line, a reset-reason register, or a corrupted output packet? Once you can describe the failure the same way every time, you can compare changes without fooling yourself.",
                ],
                "bullets": [
                    "Record firmware version, board revision, environment, and trigger steps.",
                    "Separate user-visible symptoms from inferred root causes.",
                    "Save one known-good run and one failing run for comparison.",
                ],
            },
            {
                "heading": "2. Reduce The Search Space",
                "paragraphs": [
                    "Most firmware debugging effort is wasted on searching too much system surface at once. Reduce the problem by disabling optional tasks, stubbing peripherals, freezing dynamic inputs, or reproducing the issue with a smaller command sequence. The goal is not elegance. The goal is to find a boundary where the bug appears on one side and disappears on the other.",
                    "This is also the point where static evidence helps. If you have only a firmware image, inspect strings, version markers, build paths, configuration fragments, and suspicious libraries. FirmwareLens is useful here because it organizes binary findings, risky strings, and implementation clues into a report you can review before setting up a full lab session.",
                ],
                "bullets": [
                    "Remove one variable at a time: transport, sensor input, radio state, or timing source.",
                    "Compare failing and non-failing configuration bytes or environment conditions.",
                    "Use firmware reports to identify hardcoded endpoints, keys, feature flags, and build clues.",
                ],
            },
            {
                "heading": "3. Add Instrumentation That Survives Failure",
                "paragraphs": [
                    "Printf-style logging is helpful until the system crashes before the message flushes. Add instrumentation that survives failure: boot counters, reset-reason capture, last-state markers in retained memory, watchdog breadcrumbs, and lightweight event IDs stored in a ring buffer. These traces often tell you more than a breakpoint in a Heisenbug-prone system.",
                    "For field failures, reserve a tiny amount of non-volatile or retained RAM space for the last successful subsystem transition. If the device resets during network bring-up, filesystem mount, or task creation, that breadcrumb narrows the search dramatically and makes remote support much more effective.",
                ],
                "bullets": [
                    "Persist reset reason and last completed boot stage.",
                    "Keep logs compact enough that they can survive constrained devices.",
                    "Prefer counters and state IDs when full text logging is too heavy.",
                ],
            },
            {
                "heading": "4. Close The Loop With A Triage Checklist",
                "paragraphs": [
                    "The final step is operational discipline. Once you find the issue, turn the investigation into a checklist: what signal exposed it, what tests would have caught it earlier, and which guardrail now prevents it from returning. That keeps future debugging from starting from zero.",
                    "A strong checklist usually includes unit or integration coverage, a release gate for risky config changes, and one article or internal note that explains the pattern. That content is also good SEO material because real debugging notes tend to match the phrases engineers search for when something is on fire.",
                ],
                "bullets": [
                    "Promote the root-cause signal into a permanent health check when possible.",
                    "Document the shortest reliable reproduction path.",
                    "Create internal guides around repeated failure modes such as boot loops, bus errors, or RTOS starvation.",
                ],
            },
        ],
        "cta_title": "Use FirmwareLens Early In The Triage Loop",
        "cta_body": (
            "When you need quick evidence from a firmware image, run it through FirmwareLens to inspect "
            "strings, secrets, libraries, and risky patterns before investing more bench time."
        ),
    },
    {
        "slug": "watchdog-reset-debugging",
        "title": "Watchdog Reset Debugging: How To Find The Real Cause Fast",
        "description": (
            "Learn how to debug watchdog resets by checking reset reasons, timing stalls, task starvation, "
            "interrupt lockups, and missed heartbeat logic."
        ),
        "published_at": "2026-03-27",
        "updated_at": "2026-03-27",
        "category": "Resets",
        "search_terms": [
            "watchdog reset debugging",
            "embedded watchdog troubleshooting",
            "firmware reset cause analysis",
        ],
        "intro": (
            "A watchdog reset is usually a symptom, not the bug itself. The trick is to prove why the "
            "system stopped servicing the watchdog and whether the stall was caused by timing, deadlock, "
            "memory corruption, interrupt abuse, or a bad recovery path."
        ),
        "takeaways": [
            "Confirm that the reset really came from the watchdog before changing application code.",
            "Track which task or subsystem is responsible for feeding the watchdog.",
            "Instrument the last successful milestone before reset and store it in retained memory.",
            "Fix the stall and the recovery path, not just the watchdog timeout value.",
        ],
        "sections": [
            {
                "heading": "1. Verify The Reset Source",
                "paragraphs": [
                    "Many teams call every unexpected reboot a watchdog event even when the cause is a brownout, external reset, hard fault, or bootloader handoff. Read the MCU reset-cause register at the earliest possible boot stage and preserve it before other code clears it. That single step can save days.",
                    "If you support multiple boards, compare the watchdog issue across power supplies, batteries, and temperature ranges. A power problem can look like a software stall, especially when the device resets around radio transmit or motor activity.",
                ],
                "bullets": [
                    "Capture reset reason before initialization overwrites it.",
                    "Compare behavior on lab power and field power.",
                    "Check whether bootloader and application disagree about reset handling.",
                ],
            },
            {
                "heading": "2. Find The Missing Heartbeat",
                "paragraphs": [
                    "Every watchdog design has an implicit contract: one task, interrupt, or scheduler path must prove the system is healthy often enough to feed the timer. Debugging starts by mapping that contract clearly. If the feed occurs in an idle loop, a high-priority task can starve it. If the feed occurs inside a timer callback, disabled interrupts or callback jitter can break it.",
                    "The easiest investigation is to log the last successful feed timestamp and the last code region entered before the gap. You are looking for the heartbeat that went silent. Once you know which execution path disappeared, the bug usually becomes a standard concurrency or timing problem.",
                ],
                "bullets": [
                    "Name the exact owner of the watchdog feed.",
                    "Log the feed interval instead of only the final reset.",
                    "Check for long critical sections, disabled interrupts, or blocking drivers.",
                ],
            },
            {
                "heading": "3. Common Patterns Behind Watchdog Resets",
                "paragraphs": [
                    "The repeat offenders are familiar: deadlocks around shared peripherals, infinite retry loops after a bus error, heap exhaustion leading to undefined behavior, flash operations that block too long, and priority inversions that starve the health-monitor task. Networking code is another common source when reconnect logic blocks longer than the watchdog budget.",
                    "Binary inspection helps when field firmware differs from the expected build. Look for feature flags, logging strings, server endpoints, and unexpected library versions. If a field image is feeding a different code path than the one on your desk, watchdog symptoms can stay mysterious until you confirm what binary is really deployed.",
                ],
                "bullets": [
                    "Review retry loops that can run forever under error conditions.",
                    "Check whether flash erase/write operations exceed the watchdog window.",
                    "Verify the deployed firmware image and config match the intended release.",
                ],
            },
            {
                "heading": "4. Harden Recovery, Not Just Detection",
                "paragraphs": [
                    "Once you reproduce the stall, do not stop at increasing the timeout. A good fix ensures the system fails in a controlled way, stores enough context for future diagnosis, and restores service safely after reboot. That may mean persisting a fault code, rate-limiting a failing task, or entering a degraded mode instead of full reset loops.",
                    "The best watchdog designs also include observability in release builds. If a reset happens in the field, you want a support engineer to know whether the system died in storage, networking, sensor polling, or a maintenance routine, even without a live debugger.",
                ],
                "bullets": [
                    "Persist last-known subsystem state for field analysis.",
                    "Avoid masking the issue by simply extending watchdog deadlines.",
                    "Add release-safe diagnostics that survive reboot.",
                ],
            },
        ],
        "cta_title": "Need Faster Reset Triage?",
        "cta_body": (
            "FirmwareLens helps teams inspect firmware builds, compare suspicious strings and configs, and "
            "document field failures with Sentinel Bot when debugger access is limited."
        ),
    },
    {
        "slug": "uart-vs-spi-vs-i2c-debugging",
        "title": "UART vs SPI vs I2C Debugging: What Fails, What To Measure, What To Fix",
        "description": (
            "Compare UART, SPI, and I2C debugging workflows, including the most common bus failures, "
            "signals to capture, and firmware-side checks that speed up root cause analysis."
        ),
        "published_at": "2026-03-27",
        "updated_at": "2026-03-27",
        "category": "Protocols",
        "search_terms": [
            "uart vs spi vs i2c debugging",
            "embedded bus debugging guide",
            "serial protocol troubleshooting",
        ],
        "intro": (
            "Different embedded buses fail in different ways. UART usually betrays timing or framing issues, "
            "SPI exposes chip-select and mode mistakes, and I2C punishes weak pull-ups, stuck lines, and "
            "state-machine bugs. Good debugging starts by matching your tools to the bus behavior."
        ),
        "takeaways": [
            "Pick measurements that match the protocol instead of applying one generic checklist.",
            "Verify firmware configuration against the observed waveform, not against assumptions.",
            "Capture both the electrical signal and the software event that triggered it.",
            "Use protocol-specific failure patterns to narrow the search quickly.",
        ],
        "sections": [
            {
                "heading": "1. UART: Check Timing, Framing, And Line Ownership",
                "paragraphs": [
                    "UART problems usually surface as garbage characters, partial packets, missing responses, or boot logs that look almost correct. That often points to baud mismatch, parity configuration, line inversion, or a shared pin that is switching modes at the wrong time.",
                    "A scope or logic analyzer will tell you whether the line timing matches the configured baud rate, but firmware review matters too. Check whether clocks changed after initialization, whether DMA or interrupt handlers can overrun buffers, and whether low-power transitions reconfigure the UART unexpectedly.",
                ],
                "bullets": [
                    "Confirm baud, parity, stop bits, and voltage levels on both ends.",
                    "Check buffer overruns, DMA completion timing, and sleep-state pin muxing.",
                    "Compare bootloader UART configuration with application configuration.",
                ],
            },
            {
                "heading": "2. SPI: Verify Mode, Chip Select, And Transaction Boundaries",
                "paragraphs": [
                    "SPI failures often look deceptively digital: you get data, but it is shifted, stale, or only sometimes valid. Start with clock polarity and phase, because one incorrect mode setting can make every byte appear close to correct while still being wrong.",
                    "Then look at transaction boundaries. Many bugs come from chip-select toggling too early, DMA sending one byte too many, or firmware assuming a peripheral is ready before it actually is. Capturing MOSI, MISO, clock, and chip select together usually exposes the issue quickly.",
                ],
                "bullets": [
                    "Validate CPOL and CPHA against the peripheral datasheet.",
                    "Inspect chip-select timing before, during, and after transfers.",
                    "Check whether full-duplex reads are discarding meaningful bytes.",
                ],
            },
            {
                "heading": "3. I2C: Expect Stuck Buses And Recovery Logic Problems",
                "paragraphs": [
                    "I2C debugging is often less about throughput and more about robustness. Weak pull-ups, long traces, clock stretching, address confusion, and improper bus recovery can all produce intermittent failures that only appear on one board lot or after a warm reboot.",
                    "If SDA or SCL is stuck low, the fix may live in hardware, the sensor driver, or the recovery routine. Check whether your firmware releases the bus correctly after errors and whether initialization handles devices that power up more slowly than the MCU.",
                ],
                "bullets": [
                    "Measure pull-up strength and rise times on the real hardware.",
                    "Confirm 7-bit versus 8-bit address handling in firmware.",
                    "Implement bus-clear and retry logic that avoids endless lockups.",
                ],
            },
            {
                "heading": "4. Combine Waveforms With Firmware Evidence",
                "paragraphs": [
                    "Protocol traces tell you what happened on the wires. Firmware evidence tells you why the software chose that transaction. That is why good teams pair logic captures with binary metadata, build versioning, and configuration review. A wrong bus frequency or device address is often visible in both places.",
                    "FirmwareLens does not replace a logic analyzer, but it is useful when you need quick insight from a firmware image: strings, endpoints, keys, library hints, and configuration clues can all sharpen your protocol debugging plan before you return to the bench.",
                ],
                "bullets": [
                    "Tie each waveform capture to the exact firmware build under test.",
                    "Review config constants, feature flags, and peripheral strings in the image.",
                    "Document bus-specific fixes so similar issues are faster next time.",
                ],
            },
        ],
        "cta_title": "Make Bus Failures Easier To Reproduce",
        "cta_body": (
            "Use FirmwareLens to inspect firmware builds and support notes alongside your UART, SPI, "
            "or I2C captures so protocol issues stay tied to the exact binary under investigation."
        ),
    },
    {
        "slug": "top-firmware-bugs",
        "title": "Top 10 Firmware Bugs That Commonly Reach Production",
        "description": (
            "A field-tested list of common firmware bugs, from watchdog loops and race conditions to "
            "bad state recovery, memory issues, and configuration drift."
        ),
        "published_at": "2026-03-27",
        "updated_at": "2026-03-27",
        "category": "Reliability",
        "search_terms": [
            "top firmware bugs",
            "common embedded software bugs",
            "firmware bug analysis",
        ],
        "intro": (
            "Production firmware failures are rarely exotic. They usually come from a small set of patterns "
            "that teams underestimate because the bug only appears under timing pressure, field power, or a "
            "messy upgrade path."
        ),
        "takeaways": [
            "Most recurring firmware bugs come from state handling, timing, concurrency, and configuration drift.",
            "A short pre-release checklist catches more bugs than ad hoc late-stage heroics.",
            "Field observability turns expensive mysteries into standard support incidents.",
            "Educational content around real bugs is also your strongest long-tail SEO asset.",
        ],
        "sections": [
            {
                "heading": "1. The Ten Bugs",
                "paragraphs": [
                    "The most common production firmware bugs are: watchdog feed failures, race conditions across tasks or interrupts, stack overflow, heap fragmentation, unbounded retry loops, protocol state desynchronization, bad upgrade or rollback handling, reset-reason loss, configuration mismatches across environments, and silent data corruption from unchecked bounds.",
                    "None of these are glamorous, but they are responsible for a huge share of outages, RMAs, and emergency patch releases. They also map cleanly to the search terms engineers type into Google when a device starts misbehaving in the field.",
                ],
                "bullets": [
                    "Watchdog loops",
                    "Task and interrupt races",
                    "Stack and heap failures",
                    "Protocol desync and timeout storms",
                    "Upgrade, config, and recovery path bugs",
                ],
            },
            {
                "heading": "2. Why These Bugs Escape Lab Testing",
                "paragraphs": [
                    "A lot of lab testing happens on stable power, short runtimes, and a narrow set of fixtures. Production devices see noisy input, poor connectivity, battery sag, long uptime, and rare sequences that trigger stale state. That gap is why timing bugs and recovery bugs survive all the way to customers.",
                    "Another common issue is observability. If release builds remove all useful breadcrumbs, the team learns only that 'the unit rebooted' or 'communications stopped.' Without reset reason, last successful state, or feature flags tied to the build, diagnosis becomes guesswork.",
                ],
                "bullets": [
                    "Test long-duration and degraded-network behavior, not only happy paths.",
                    "Retain lightweight breadcrumbs in production builds.",
                    "Review upgrade and rollback paths with the same seriousness as first boot.",
                ],
            },
            {
                "heading": "3. Prevention Habits That Pay Off",
                "paragraphs": [
                    "Simple habits catch a surprising number of bugs: define timeout budgets, cap retries, assert impossible states in development builds, log reset reasons, check task stack high-water marks, and include a release checklist for config compatibility. These are boring safeguards, but boring safeguards are what keep field incidents small.",
                    "When you handle firmware as both a product and a support surface, content improves too. Every postmortem can become a short engineering guide. That guide helps your own team onboard faster and helps search engines understand what problems your product is genuinely relevant to.",
                ],
                "bullets": [
                    "Track stack usage and heap headroom before release.",
                    "Require explicit recovery behavior for each communications failure mode.",
                    "Store enough version and config metadata to identify the deployed image quickly.",
                ],
            },
            {
                "heading": "4. Use The Bug List As A Release Gate",
                "paragraphs": [
                    "A short bug-pattern checklist is more useful than a giant theoretical rubric. Before each release, ask whether any recent changes touched watchdog logic, task priorities, memory use, upgrade flow, communication timeouts, or persisted config. Those questions align directly with the bugs that create real support load.",
                    "If you pair that checklist with FirmwareLens scans, report export, and field issue notes, you also create a cleaner record of what shipped and what signals were reviewed. That helps both engineering discipline and future trust with users.",
                ],
                "bullets": [
                    "Turn common bugs into explicit go/no-go release questions.",
                    "Save scan reports and support notes alongside each important build.",
                    "Promote repeated field failures into permanent regression tests.",
                ],
            },
        ],
        "cta_title": "Build A Better Release Checklist",
        "cta_body": (
            "FirmwareLens can support release reviews with binary findings, readable reports, and saved "
            "evidence that complements your reliability and debugging checklist."
        ),
    },
    {
        "slug": "rtos-debugging-guide",
        "title": "RTOS Debugging Guide: Task Starvation, Priority Inversion, And Timing Bugs",
        "description": (
            "A practical RTOS debugging guide for task starvation, priority inversion, mutex issues, "
            "stack problems, and scheduler-related failures in embedded systems."
        ),
        "published_at": "2026-03-27",
        "updated_at": "2026-03-27",
        "category": "RTOS",
        "search_terms": [
            "rtos debugging guide",
            "task starvation debugging",
            "priority inversion embedded",
        ],
        "intro": (
            "RTOS bugs are hard because the system is often doing exactly what you told it to do, just not "
            "what you intended. Scheduler behavior, priorities, mutexes, and interrupts interact in ways "
            "that can look random until you instrument the right state."
        ),
        "takeaways": [
            "Measure task timing and scheduler behavior before assuming memory corruption.",
            "Track stack usage, mutex ownership, and blocked-state duration in release-friendly ways.",
            "Priority problems are usually architecture problems, not just tuning problems.",
            "Document RTOS failure signatures as clearly as hardware faults.",
        ],
        "sections": [
            {
                "heading": "1. Start With The Scheduler Story",
                "paragraphs": [
                    "When an RTOS system misses deadlines or becomes unresponsive, the first question is not 'which line crashed?' but 'which task stopped making progress and why?' Build a scheduler story: which tasks should run, at what priority, with what deadlines, and what resource each one waits on.",
                    "That story exposes mismatches quickly. A logging task running too high can starve real work. A maintenance task that holds a mutex during flash I/O can delay an urgent control task. Once you map the intended scheduler behavior, deviations become visible.",
                ],
                "bullets": [
                    "List tasks, priorities, period, deadline, and critical resources.",
                    "Capture blocked time and run time for suspicious tasks.",
                    "Review whether interrupt handlers are doing work that belongs in tasks.",
                ],
            },
            {
                "heading": "2. Watch For Priority Inversion And Starvation",
                "paragraphs": [
                    "Priority inversion happens when a low-priority task holds a resource that a high-priority task needs, while some medium-priority task keeps running and prevents the low-priority owner from releasing it. The symptom can look like random jitter, watchdog resets, or total UI freezes.",
                    "Starvation is broader: a task that should run simply does not get enough time because the system budget is already spent. Measure queue depth, wait time, and missed periods. If you cannot explain who owns CPU time, you cannot debug an RTOS issue reliably.",
                ],
                "bullets": [
                    "Use mutex priority inheritance when appropriate.",
                    "Measure queue backlog and deadline misses, not only crashes.",
                    "Check whether worker tasks accidentally became high-priority forever loops.",
                ],
            },
            {
                "heading": "3. Rule Out Stack And Heap Problems",
                "paragraphs": [
                    "RTOS systems often fail because of memory pressure wearing a concurrency mask. A stack overflow may corrupt a neighboring task control block and produce symptoms that look like a scheduling bug. Heap fragmentation can break message allocation only after hours of uptime.",
                    "Track stack high-water marks continuously in testing and keep guard patterns where the RTOS allows it. For dynamic allocation, log failure counts and heap watermark trends so the issue is visible before the system tips into undefined behavior.",
                ],
                "bullets": [
                    "Measure stack headroom per task after real workloads, not synthetic idle runs.",
                    "Prefer fixed-size pools for high-frequency RTOS paths when possible.",
                    "Record allocation failures and heap low-water marks in the field.",
                ],
            },
            {
                "heading": "4. Tie RTOS Symptoms Back To The Shipped Firmware",
                "paragraphs": [
                    "An RTOS bug investigation gets much easier when you know exactly which image is running, what feature flags are active, and whether a field unit is using a different scheduler configuration than the lab build. That is why firmware metadata matters even in timing-heavy investigations.",
                    "FirmwareLens helps at that stage by surfacing build clues, risky strings, library evidence, and report artifacts you can attach to the incident. It will not replace RTOS trace tooling, but it keeps the binary and the debugging record connected.",
                ],
                "bullets": [
                    "Tie RTOS traces to exact build identifiers and config values.",
                    "Save incident notes with the matching firmware report.",
                    "Convert every confirmed RTOS failure pattern into a documented playbook.",
                ],
            },
        ],
        "cta_title": "Make RTOS Incidents Easier To Explain",
        "cta_body": (
            "Pair your RTOS trace tools with FirmwareLens reports and support notes so scheduler bugs stay "
            "connected to the exact build, evidence, and follow-up actions."
        ),
    },
]


def _word_count(post):
    words = []
    words.extend(post.get("title", "").split())
    words.extend(post.get("description", "").split())
    words.extend(post.get("intro", "").split())
    for item in post.get("takeaways", []):
        words.extend(item.split())
    for section in post.get("sections", []):
        words.extend(section.get("heading", "").split())
        for paragraph in section.get("paragraphs", []):
            words.extend(paragraph.split())
        for bullet in section.get("bullets", []):
            words.extend(bullet.split())
    words.extend(post.get("cta_title", "").split())
    words.extend(post.get("cta_body", "").split())
    return len(words)


def _with_derived_fields(post):
    word_count = _word_count(post)
    return {
        **post,
        "path": f"/blog/{post['slug']}",
        "word_count": word_count,
        "reading_time_minutes": max(4, ceil(word_count / 180)),
    }


BLOG_POSTS = [_with_derived_fields(post) for post in RAW_BLOG_POSTS]
BLOG_POSTS_BY_SLUG = {post["slug"]: post for post in BLOG_POSTS}


def related_posts_for(slug, limit=3):
    return [post for post in BLOG_POSTS if post["slug"] != slug][:limit]
