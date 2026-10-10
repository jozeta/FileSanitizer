import re
from typing import List, Dict, Any, Optional
from app.analyzers.base import Finding
from app.core.settings_store import settings_store
from app.core.logging_config import logger

class WatchlistAnalyzer:
    """
    Scans extracted text streams, document bodies, metadata, script code,
    and OCR text against administrator-configured Warninglist / Watchlist rules.
    Supports simple keywords, phrases, and regular expressions with custom severity levels.
    """

    @classmethod
    def scan_text(cls, text_corpus: str, source_label: str = "document content") -> List[Finding]:
        if not text_corpus or not text_corpus.strip():
            return []

        findings: List[Finding] = []
        rules = settings_store.get_warning_rules()
        active_rules = [r for r in rules if r.get("enabled", True)]

        for rule in active_rules:
            pattern_str = rule.get("pattern", "").strip()
            if not pattern_str:
                continue

            is_regex = rule.get("is_regex", False)
            severity = rule.get("severity", "medium").lower()
            if severity == "informational":
                severity = "info"
            if severity not in ["info", "low", "medium", "high", "critical"]:
                severity = "medium"

            matched = False
            snippet = ""
            detected_val = ""

            try:
                if is_regex:
                    match = re.search(pattern_str, text_corpus, re.IGNORECASE)
                    if match:
                        matched = True
                        detected_val = match.group(0)
                        start = max(0, match.start() - 40)
                        end = min(len(text_corpus), match.end() + 40)
                        snippet = text_corpus[start:end].replace("\n", " ").strip()
                else:
                    idx = text_corpus.lower().find(pattern_str.lower())
                    if idx != -1:
                        matched = True
                        detected_val = text_corpus[idx:idx + len(pattern_str)]
                        start = max(0, idx - 40)
                        end = min(len(text_corpus), idx + len(pattern_str) + 40)
                        snippet = text_corpus[start:end].replace("\n", " ").strip()
            except Exception as e:
                logger.debug(f"Watchlist scan error on rule '{pattern_str}': {e}")
                continue

            if matched:
                rule_name = rule.get("name")
                if not rule_name or not rule_name.strip():
                    desc = rule.get("description", "").strip()
                    if desc and len(desc) <= 50:
                        rule_name = desc
                    elif "pnr" in str(rule.get("id")):
                        rule_name = "Swedish Personnummer"
                    elif "credit-card" in str(rule.get("id")):
                        rule_name = "Credit Card Number"
                    elif "email" in str(rule.get("id")):
                        rule_name = "Email Address"
                    elif "iban" in str(rule.get("id")):
                        rule_name = "IBAN Number"
                    elif "jwt" in str(rule.get("id")):
                        rule_name = "JSON Web Token (JWT)"
                    elif "api-key" in str(rule.get("id")):
                        rule_name = "API Key / Secret Token"
                    else:
                        rule_name = pattern_str

                desc = rule.get("description", "").strip()
                finding_desc = (
                    f"Warninglist rule '{rule_name}' was triggered in {source_label}. "
                    f"Detected value: \"{detected_val}\". "
                    f"Context snippet: \"...{snippet}...\""
                )
                if desc and desc != rule_name:
                    finding_desc += f" (Rule Note: {desc})"

                findings.append(Finding(
                    category="warninglist",
                    severity=severity,
                    title=f"Warninglist Rule Triggered: {rule_name}",
                    description=finding_desc,
                    details={
                        "rule_id": rule.get("id"),
                        "rule_name": rule_name,
                        "detected_value": detected_val,
                        "pattern": pattern_str,
                        "is_regex": is_regex,
                        "severity": severity,
                        "matched_context": snippet,
                        "source": source_label
                    }
                ))

        return findings
