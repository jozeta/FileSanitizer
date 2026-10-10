"""
Data Loss Prevention (DLP), Exfiltration & Leaked Secrets Analyzer.
Scans text, scripts, documents, emails, and extracted streams for leaked credentials,
cloud tokens, private cryptographic keys, and sensitive financial/PII records.
"""

import re
from typing import List, Dict, Any, Optional, Tuple
from app.analyzers.base import Finding


def _luhn_check(number_str: str) -> bool:
    """Validate credit card number using Luhn mod-10 algorithm."""
    digits = [int(c) for c in number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    # All same digits is invalid (e.g. 0000000000000000)
    if len(set(digits)) == 1:
        return False

    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = d * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += d
    return (checksum % 10) == 0


def _iban_check(iban_str: str) -> bool:
    """Validate International Bank Account Number using mod-97 check (ISO 13616)."""
    clean = re.sub(r'[\s\-]', '', iban_str).upper()
    if len(clean) < 15 or len(clean) > 34:
        return False
    if not clean[:2].isalpha() or not clean[2:4].isdigit():
        return False

    # Rearrange: move country code & check digits to the end
    rearranged = clean[4:] + clean[:4]
    # Replace letters with digits: A=10, B=11, ..., Z=35
    numeric_str = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
    try:
        return int(numeric_str) % 97 == 1
    except ValueError:
        return False


def _redact(val: str, keep_start: int = 4, keep_end: int = 4) -> str:
    """Redact sensitive value for safe display in findings."""
    val = val.strip()
    if len(val) <= (keep_start + keep_end):
        return "*" * len(val)
    return f"{val[:keep_start]}{'*' * (len(val) - keep_start - keep_end)}{val[-keep_end:]}"


class DLPAnalyzer:
    """Detects leaked credentials, private keys, API secrets, and financial/PII data."""

    # Precompiled regex patterns
    PATTERNS = {
        "aws_access_key": (
            re.compile(r'\b(AKIA[0-9A-Z]{16})\b'),
            "critical",
            "AWS Access Key ID",
            "Discovered active AWS IAM/Root Access Key ID. Enables direct AWS API authentication."
        ),
        "aws_secret_key": (
            re.compile(r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*[\'"]?([a-zA-Z0-9/+]{40})[\'"]?'),
            "critical",
            "AWS Secret Access Key",
            "Discovered AWS Secret Access Key configuration parameter."
        ),
        "github_token": (
            re.compile(r'\b(gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{82})\b'),
            "critical",
            "GitHub Personal Access Token",
            "Discovered GitHub authentication token with repository and org permissions."
        ),
        "slack_webhook": (
            re.compile(r'https://hooks\.slack\.com/services/(T[A-Za-z0-9_-]+/B[A-Za-z0-9_-]+/[A-Za-z0-9_-]+)'),
            "high",
            "Slack Incoming Webhook URL",
            "Discovered unauthenticated Slack webhook URL enabling unauthorized channel messaging."
        ),
        "slack_token": (
            re.compile(r'\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b'),
            "critical",
            "Slack API Bot/User Token",
            "Discovered Slack API token enabling workspace automation and conversation extraction."
        ),
        "openai_api_key": (
            re.compile(r'\b(sk-[a-zA-Z0-9]{20,}|sk-proj-[a-zA-Z0-9_-]{20,})\b'),
            "high",
            "OpenAI API Key",
            "Discovered OpenAI / AI Platform API key credential."
        ),
        "anthropic_api_key": (
            re.compile(r'\b(sk-ant-[a-zA-Z0-9_-]{20,})\b'),
            "high",
            "Anthropic API Key",
            "Discovered Anthropic Claude API key credential."
        ),
        "private_key": (
            re.compile(r'-----BEGIN (?:RSA|OPENSSH|EC|DSA|PGP)? ?PRIVATE KEY-----'),
            "critical",
            "Cryptographic Private Key Block",
            "Discovered unencrypted RSA/OpenSSH/EC private key. Grants direct system access or certificate impersonation."
        ),
        "generic_api_secret": (
            re.compile(r'(?i)(?:api[_-]?key|access[_-]?token|client[_-]?secret|auth[_-]?token)\s*[:=]\s*[\'"]([a-zA-Z0-9_\-\.]{24,})[\'"]'),
            "high",
            "Generic Hardcoded API Secret / Bearer Token",
            "Discovered hardcoded credential or authentication secret assignment."
        ),
        "ssn": (
            re.compile(r'\b(?!000|666|9\d{2})(\d{3})-(?!00)(\d{2})-(?!0000)(\d{4})\b'),
            "high",
            "US Social Security Number (SSN)",
            "Discovered Personally Identifiable Information (PII): valid US Social Security Number."
        ),
    }

    # Credit card regex: matches 13-19 digits formatted with spaces/dashes or continuous
    CC_REGEX = re.compile(
        r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|2[2-7][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b'
    )
    CC_DELIM_REGEX = re.compile(
        r'\b(?:\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}|\d{4}[ -]\d{6}[ -]\d{5})\b'
    )

    # IBAN regex candidate
    IBAN_REGEX = re.compile(r'\b[A-Z]{2}[0-9]{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b')

    @classmethod
    def scan_text(cls, text: str, source_label: str = "content") -> List[Finding]:
        """Scan string content for sensitive secrets and DLP indicators."""
        if not text or len(text.strip()) < 10:
            return []

        findings: List[Finding] = []
        found_types: Dict[str, List[str]] = {}

        # 1. Regex Rule Matching
        for rule_id, (pattern, severity, title, desc) in cls.PATTERNS.items():
            matches = pattern.findall(text)
            if matches:
                redacted_list = []
                for m in matches[:5]:
                    raw_val = m if isinstance(m, str) else (m[0] if isinstance(m, tuple) else str(m))
                    if raw_val:
                        redacted_list.append(_redact(raw_val))

                findings.append(Finding(
                    category="dlp",
                    severity=severity,
                    title=f"DLP Indicator: {title} ({len(matches)} occurrence{'s' if len(matches) > 1 else ''})",
                    description=f"{desc} Discovered in {source_label}.",
                    details={
                        "rule_id": rule_id,
                        "type": title,
                        "count": len(matches),
                        "redacted_samples": redacted_list,
                        "source": source_label
                    }
                ))

        # 2. Credit Card Numbers (with Luhn validation)
        valid_cards = []
        # Continuous numbers
        for cc_cand in cls.CC_REGEX.findall(text):
            if _luhn_check(cc_cand):
                valid_cards.append(cc_cand)

        # Delimited numbers (1234-5678-9012-3456)
        for cc_delim in cls.CC_DELIM_REGEX.findall(text):
            cleaned = re.sub(r'[\s\-]', '', cc_delim)
            if _luhn_check(cleaned) and cleaned not in valid_cards:
                valid_cards.append(cleaned)

        if valid_cards:
            redacted_ccs = [_redact(c, keep_start=4, keep_end=4) for c in valid_cards[:5]]
            findings.append(Finding(
                category="dlp",
                severity="critical",
                title=f"DLP Alert: Valid Payment Card Numbers Detected ({len(valid_cards)} card{'s' if len(valid_cards) > 1 else ''})",
                description=(
                    f"Discovered {len(valid_cards)} credit/debit card numbers in {source_label} verified against "
                    "the Luhn (mod-10) checksum algorithm. Exfiltration of cardholder data violates PCI-DSS."
                ),
                details={
                    "rule_id": "credit_card_luhn",
                    "type": "Payment Card (PCI-DSS)",
                    "count": len(valid_cards),
                    "redacted_samples": redacted_ccs,
                    "source": source_label
                }
            ))

        # 3. IBAN Bank Accounts (with mod-97 validation)
        valid_ibans = []
        for iban_cand in cls.IBAN_REGEX.findall(text):
            if _iban_check(iban_cand):
                valid_ibans.append(iban_cand.replace(" ", ""))

        if valid_ibans:
            redacted_ibans = [_redact(i, keep_start=4, keep_end=3) for i in valid_ibans[:5]]
            findings.append(Finding(
                category="dlp",
                severity="high",
                title=f"DLP Alert: Valid IBAN Bank Accounts Detected ({len(valid_ibans)} account{'s' if len(valid_ibans) > 1 else ''})",
                description=(
                    f"Discovered {len(valid_ibans)} International Bank Account Numbers (IBAN) in {source_label} "
                    "passing ISO 13616 Mod-97 checksum validation."
                ),
                details={
                    "rule_id": "iban_bank_account",
                    "type": "Bank Account (IBAN)",
                    "count": len(valid_ibans),
                    "redacted_samples": redacted_ibans,
                    "source": source_label
                }
            ))

        return findings
