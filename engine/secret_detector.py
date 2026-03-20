import re


PASSWORD_MARKERS = ("password=", "passwd=", "pwd=")
API_KEY_MARKERS = ("api_key", "apikey")
JWT_PART_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")
AWS_ACCESS_KEY_PATTERN = re.compile(r"AKIA[0-9A-Z]{16}")
POSSIBLE_API_KEY_PATTERN = re.compile(r"^[A-Za-z0-9_-]{20,}$")
ENCODED_SECRET_PATTERN = re.compile(r"^[A-Za-z0-9+/=]{20,}$")
PRIVATE_KEY_MARKER = "BEGIN PRIVATE KEY"


def _compile_pattern_specs(patterns):
    compiled = []
    for spec in patterns:
        pattern, *rest = spec
        compiled.append((re.compile(pattern, re.IGNORECASE), *rest))
    return tuple(compiled)


WEAK_CRYPTO_PATTERNS = _compile_pattern_specs(
    [
        (r"\bmd5\b", "Weak Crypto (MD5)", "HIGH", "MD5 is cryptographically broken and should not be used."),
        (r"\bsha1\b", "Weak Crypto (SHA1)", "MEDIUM", "SHA-1 is deprecated for security-sensitive use."),
        (r"\bdes\b", "Weak Crypto (DES)", "HIGH", "DES is obsolete and vulnerable to brute-force attacks."),
        (r"\b3des\b", "Weak Crypto (3DES)", "MEDIUM", "3DES is deprecated and should be replaced."),
        (r"\brc4\b", "Weak Crypto (RC4)", "HIGH", "RC4 is insecure and should not protect device traffic."),
    ]
)

OUTDATED_LIBRARY_PATTERNS = _compile_pattern_specs(
    [
        (r"openssl[\s/_-]?1\.0\.", "Outdated Library", "HIGH"),
        (r"openssl[\s/_-]?1\.1\.0", "Outdated Library", "MEDIUM"),
        (r"busybox[\s/_-]?1\.(1\d|2\d)", "Outdated Library", "MEDIUM"),
        (r"dropbear[\s/_-]?20(1\d|2[0-2])", "Outdated Library", "MEDIUM"),
    ]
)

SUSPICIOUS_STRING_PATTERNS = _compile_pattern_specs(
    [
        (r"\bbackdoor\b", "Suspicious String", "HIGH"),
        (r"\btelnetd\b", "Suspicious String", "MEDIUM"),
        (r"\bdebug=true\b", "Suspicious String", "MEDIUM"),
        (r"\bunsigned update\b", "Suspicious String", "HIGH"),
        (r"\bskip[_ -]?verify\b", "Suspicious String", "HIGH"),
    ]
)

BAD_PRACTICE_PATTERNS = _compile_pattern_specs(
    [
        (r"\bstrcpy\s*\(", "Bad Practice", "HIGH", "Unsafe string copy usage may enable memory corruption."),
        (r"\bgets\s*\(", "Bad Practice", "CRITICAL", "Unbounded input handling is dangerous in native code paths."),
        (r"\bsprintf\s*\(", "Bad Practice", "HIGH", "Unbounded formatted writes can cause buffer overflows."),
        (r"\bsystem\s*\(", "Bad Practice", "MEDIUM", "Shell execution primitives can expand the attack surface."),
        (r"\b/tmp/\b", "Bad Practice", "LOW", "Temporary-path usage may indicate weak file handling or unsafe storage."),
        (r"\bchmod\s+777\b", "Bad Practice", "HIGH", "World-writable permissions create avoidable risk."),
        (r"\bdefault_password\b", "Bad Practice", "HIGH", "Default credential patterns should not ship in production firmware."),
    ]
)


def is_readable(value):
    return value.isascii() and value.isprintable()


def is_valid_jwt(value):
    parts = value.split(".")
    if len(parts) != 3:
        return False

    for part in parts:
        if len(part) < 10 or not JWT_PART_PATTERN.fullmatch(part):
            return False

    return True


def detect_secrets(strings):
    return _detect_findings(strings, include_basic=True, include_advanced=False)


def detect_advanced_secrets(strings):
    return _detect_findings(strings, include_basic=False, include_advanced=True)


def detect_all_findings(strings):
    return _detect_findings(strings, include_basic=True, include_advanced=True)


def _detect_findings(strings, include_basic, include_advanced):
    findings = []

    for value in strings:
        lowered = value.lower()

        if include_basic:
            findings.extend(_detect_basic_findings(value, lowered))
        if include_advanced:
            findings.extend(_detect_advanced_findings(value, lowered))

    return findings


def _detect_basic_findings(value, lowered):
    findings = []

    if any(marker in lowered for marker in PASSWORD_MARKERS):
        findings.append(
            {
                "type": "Hardcoded Password",
                "value": value,
                "severity": "HIGH",
                "description": "Hardcoded credentials found inside firmware",
                "impact": "Attackers can extract credentials and gain unauthorized access",
                "recommendation": "Remove hardcoded credentials and use secure storage",
            }
        )

    if any(marker in lowered for marker in API_KEY_MARKERS):
        findings.append(
            {
                "type": "API Key",
                "value": value,
                "severity": "HIGH",
                "description": "API key exposed in firmware",
                "impact": "Unauthorized API access possible",
                "recommendation": "Store keys securely and rotate them",
            }
        )

    return findings


def _detect_advanced_findings(value, lowered):
    if not is_readable(value):
        return []

    if is_valid_jwt(value):
        return [
            {
                "type": "JWT Token",
                "value": value,
                "severity": "HIGH",
                "description": "JWT token found in firmware",
                "impact": "Could allow unauthorized access if valid",
                "recommendation": "Do not store tokens in firmware",
            }
        ]

    if AWS_ACCESS_KEY_PATTERN.search(value):
        return [
            {
                "type": "AWS Access Key",
                "value": value,
                "severity": "CRITICAL",
                "description": "AWS access key found",
                "impact": "Full access to AWS resources possible",
                "recommendation": "Revoke and rotate immediately",
            }
        ]

    if PRIVATE_KEY_MARKER in value:
        return [
            {
                "type": "Private Key",
                "value": value,
                "severity": "CRITICAL",
                "description": "Private key exposed",
                "impact": "Complete system compromise possible",
                "recommendation": "Remove keys and use secure storage",
            }
        ]

    findings = []

    if POSSIBLE_API_KEY_PATTERN.fullmatch(value):
        if any(char.isdigit() for char in value) and any(char.isalpha() for char in value):
            findings.append(
                {
                    "type": "Possible API Key",
                    "value": value,
                    "severity": "MEDIUM",
                    "description": "Possible API key detected",
                    "impact": "May allow unauthorized access",
                    "recommendation": "Verify and secure the key",
                }
            )

    if ENCODED_SECRET_PATTERN.fullmatch(value):
        findings.append(
            {
                "type": "Encoded Secret",
                "value": value,
                "severity": "MEDIUM",
                "description": "Encoded data found (possible secret)",
                "impact": "May contain sensitive information",
                "recommendation": "Decode and verify contents",
            }
        )

    if ("http://" in lowered or "https://" in lowered) and "@" in value:
        findings.append(
            {
                "type": "Credential Leak in URL",
                "value": value,
                "severity": "HIGH",
                "description": "Credentials found in URL",
                "impact": "Sensitive data exposure",
                "recommendation": "Remove credentials from URLs",
            }
        )

    findings.extend(_detect_weak_crypto(value, lowered))
    findings.extend(_detect_outdated_libraries(value, lowered))
    findings.extend(_detect_suspicious_strings(value, lowered))
    findings.extend(_detect_bad_practices(value, lowered))
    return findings


def _detect_weak_crypto(value, lowered):
    findings = []
    for pattern, label, severity, description in WEAK_CRYPTO_PATTERNS:
        if pattern.search(lowered):
            findings.append(
                {
                    "type": label,
                    "value": value,
                    "severity": severity,
                    "description": description,
                    "impact": "Weak cryptography can reduce device trust and expose sensitive communications.",
                    "recommendation": "Upgrade to modern cryptographic primitives and validate implementation paths.",
                }
            )
    return findings


def _detect_outdated_libraries(value, lowered):
    findings = []
    for pattern, label, severity in OUTDATED_LIBRARY_PATTERNS:
        if pattern.search(lowered):
            findings.append(
                {
                    "type": label,
                    "value": value,
                    "severity": severity,
                    "description": "An outdated component or library version string was detected.",
                    "impact": "Known vulnerabilities in embedded components can lead to patching cost and exploit risk.",
                    "recommendation": "Inventory the component and upgrade to a supported version before release.",
                }
            )
    return findings


def _detect_suspicious_strings(value, lowered):
    findings = []
    for pattern, label, severity in SUSPICIOUS_STRING_PATTERNS:
        if pattern.search(lowered):
            findings.append(
                {
                    "type": label,
                    "value": value,
                    "severity": severity,
                    "description": "A suspicious operational or debugging string was found in firmware.",
                    "impact": "Debug or bypass markers may expose unsafe behavior paths in production firmware.",
                    "recommendation": "Review the referenced code path and remove unsafe debug or bypass behavior.",
                }
            )
    return findings


def _detect_bad_practices(value, lowered):
    findings = []
    for pattern, label, severity, description in BAD_PRACTICE_PATTERNS:
        if pattern.search(lowered):
            findings.append(
                {
                    "type": label,
                    "value": value,
                    "severity": severity,
                    "description": description,
                    "impact": "Unsafe implementation patterns can turn ordinary bugs into exploitable device behavior.",
                    "recommendation": "Review the referenced pattern and replace it with safer implementation or configuration choices.",
                }
            )
    return findings
