import re


WEAK_CRYPTO_PATTERNS = [
    (r"\bmd5\b", "Weak Crypto (MD5)", "HIGH", "MD5 is cryptographically broken and should not be used."),
    (r"\bsha1\b", "Weak Crypto (SHA1)", "MEDIUM", "SHA-1 is deprecated for security-sensitive use."),
    (r"\bdes\b", "Weak Crypto (DES)", "HIGH", "DES is obsolete and vulnerable to brute-force attacks."),
    (r"\b3des\b", "Weak Crypto (3DES)", "MEDIUM", "3DES is deprecated and should be replaced."),
    (r"\brc4\b", "Weak Crypto (RC4)", "HIGH", "RC4 is insecure and should not protect device traffic."),
]

OUTDATED_LIBRARY_PATTERNS = [
    (r"openssl[\s/_-]?1\.0\.", "Outdated Library", "HIGH"),
    (r"openssl[\s/_-]?1\.1\.0", "Outdated Library", "MEDIUM"),
    (r"busybox[\s/_-]?1\.(1\d|2\d)", "Outdated Library", "MEDIUM"),
    (r"dropbear[\s/_-]?20(1\d|2[0-2])", "Outdated Library", "MEDIUM"),
]

SUSPICIOUS_STRING_PATTERNS = [
    (r"\bbackdoor\b", "Suspicious String", "HIGH"),
    (r"\btelnetd\b", "Suspicious String", "MEDIUM"),
    (r"\bdebug=true\b", "Suspicious String", "MEDIUM"),
    (r"\bunsigned update\b", "Suspicious String", "HIGH"),
    (r"\bskip[_ -]?verify\b", "Suspicious String", "HIGH"),
]

BAD_PRACTICE_PATTERNS = [
    (r"\bstrcpy\s*\(", "Bad Practice", "HIGH", "Unsafe string copy usage may enable memory corruption."),
    (r"\bgets\s*\(", "Bad Practice", "CRITICAL", "Unbounded input handling is dangerous in native code paths."),
    (r"\bsprintf\s*\(", "Bad Practice", "HIGH", "Unbounded formatted writes can cause buffer overflows."),
    (r"\bsystem\s*\(", "Bad Practice", "MEDIUM", "Shell execution primitives can expand the attack surface."),
    (r"\b/tmp/\b", "Bad Practice", "LOW", "Temporary-path usage may indicate weak file handling or unsafe storage."),
    (r"\bchmod\s+777\b", "Bad Practice", "HIGH", "World-writable permissions create avoidable risk."),
    (r"\bdefault_password\b", "Bad Practice", "HIGH", "Default credential patterns should not ship in production firmware."),
]


def is_readable(s):
    return all(32 <= ord(c) <= 126 for c in s)


def is_valid_jwt(s):
    parts = s.split(".")

    if len(parts) != 3:
        return False

    for part in parts:
        if not re.match(r"^[A-Za-z0-9_-]+$", part):
            return False
        if len(part) < 10:
            return False

    return True


def detect_secrets(strings):
    findings = []

    for value in strings:
        lowered = value.lower()

        if any(token in lowered for token in ["password=", "passwd=", "pwd="]):
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

        if "api_key" in lowered or "apikey" in lowered:
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


def detect_advanced_secrets(strings):
    findings = []

    for value in strings:
        if not is_readable(value):
            continue

        lowered = value.lower()

        if is_valid_jwt(value):
            findings.append(
                {
                    "type": "JWT Token",
                    "value": value,
                    "severity": "HIGH",
                    "description": "JWT token found in firmware",
                    "impact": "Could allow unauthorized access if valid",
                    "recommendation": "Do not store tokens in firmware",
                }
            )
            continue

        if re.search(r"AKIA[0-9A-Z]{16}", value):
            findings.append(
                {
                    "type": "AWS Access Key",
                    "value": value,
                    "severity": "CRITICAL",
                    "description": "AWS access key found",
                    "impact": "Full access to AWS resources possible",
                    "recommendation": "Revoke and rotate immediately",
                }
            )
            continue

        if "BEGIN PRIVATE KEY" in value:
            findings.append(
                {
                    "type": "Private Key",
                    "value": value,
                    "severity": "CRITICAL",
                    "description": "Private key exposed",
                    "impact": "Complete system compromise possible",
                    "recommendation": "Remove keys and use secure storage",
                }
            )
            continue

        if re.match(r"^[A-Za-z0-9_\-]{20,}$", value):
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

        if re.match(r"^[A-Za-z0-9+/=]{20,}$", value):
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

        if ("http://" in value or "https://" in value) and "@" in value:
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
        if re.search(pattern, lowered):
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
        if re.search(pattern, lowered):
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
        if re.search(pattern, lowered):
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
        if re.search(pattern, lowered):
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
