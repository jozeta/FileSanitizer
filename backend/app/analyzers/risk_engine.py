from typing import List, Dict, Any, Tuple
from app.analyzers.base import Finding
from pydantic import BaseModel, Field

class RiskAssessment(BaseModel):
    level: str  # "CLEAN", "LOW RISK", "MEDIUM RISK", "HIGH RISK", "MALICIOUS"
    score: int  # 0 to 100
    reasons: List[str] = Field(default_factory=list)
    recommendation: str
    suggested_profile: str  # "minimal", "privacy", "security", "maximum"
    allow_download_original: bool = True
    allow_sanitization: bool = True

class RiskEngine:
    """
    Explainable, deterministic risk evaluation engine.
    Calculates overall security state based on findings from all scanners.
    """

    @classmethod
    def evaluate(
        cls,
        findings: List[Finding],
        clamav_status: str,
        category: str,
        has_macros: bool = False,
        has_javascript: bool = False,
        has_path_traversal: bool = False,
        is_zip_bomb: bool = False,
        has_executable: bool = False,
        is_mismatch: bool = False
    ) -> RiskAssessment:
        reasons = []
        score = 0

        # 1. Check for Active Malware
        if clamav_status == "MALICIOUS":
            for f in findings:
                if f.category == "malware" and f.severity == "critical":
                    reasons.append(f"⚠ {f.title}")
            return RiskAssessment(
                level="MALICIOUS",
                score=100,
                reasons=reasons or ["⚠ Detected by malware scanner"],
                recommendation=(
                    "MALICIOUS CONTENT DETECTED. The file was identified as malware by the antivirus scanner. "
                    "The original file must not be downloaded or distributed. "
                    "Automated sanitization is not guaranteed to make malicious binaries safe."
                ),
                suggested_profile="maximum",
                allow_download_original=False,
                allow_sanitization=False
            )

        # 2. Critical Indicators -> HIGH RISK
        critical_reasons = []
        if has_macros:
            critical_reasons.append("⚠ Visual Basic for Applications (VBA) macros detected")
            score += 40

        if has_javascript:
            critical_reasons.append("⚠ Executable JavaScript detected")
            score += 35

        if has_path_traversal:
            critical_reasons.append("⚠ Archive contains path traversal entries (..)")
            score += 50

        if is_zip_bomb:
            critical_reasons.append("⚠ Archive exhibits zip-bomb characteristics (excessive size/files)")
            score += 50

        if has_executable:
            critical_reasons.append("⚠ Contains executable binaries or system scripts")
            score += 45

        if is_mismatch:
            critical_reasons.append("⚠ MIME type / file extension spoofing detected")
            score += 30

        # Collect other findings
        for f in findings:
            if f.severity in ["critical", "high"]:
                reason_text = f"⚠ {f.title}"
                if reason_text not in critical_reasons:
                    critical_reasons.append(reason_text)
                    score += 25
            elif f.severity == "medium":
                score += 15
            elif f.severity == "low":
                score += 5

        # 3. Determine Level
        if score >= 60 or critical_reasons:
            level = "HIGH RISK"
            rec = (
                "The file contains active executable content, structural anomalies, or dangerous references. "
                "Do not distribute the original file. Use Maximum Sanitization (Content Disarm and Reconstruction) "
                "to strip all active code before sharing."
            )
            suggested = "maximum"
            reasons = critical_reasons

        elif score >= 25:
            level = "MEDIUM RISK"
            rec = (
                "The file contains embedded external resources, sensitive metadata (e.g. GPS), or interactive elements. "
                "Recommended action: Use Security or Privacy Sanitization."
            )
            suggested = "security"
            for f in findings:
                if f.severity in ["medium", "high"]:
                    reasons.append(f"• {f.title}")

        elif score > 0:
            level = "LOW RISK"
            rec = (
                "The file contains no detected active content or suspicious embedded objects. "
                "Recommended action: Remove metadata before sharing."
            )
            suggested = "privacy"
            for f in findings:
                if f.category == "metadata":
                    reasons.append(f"• {f.title}")
            if not reasons:
                reasons.append("• Minor metadata tags present")

        else:
            level = "CLEAN"
            rec = (
                "No active content, suspicious URLs, or sensitive metadata detected. "
                "The file appears clean under current scanner heuristics."
            )
            suggested = "minimal"
            reasons.append("✓ No threats, active code, or sensitive tags detected")

        # Cap score at 100
        score = min(score, 99)

        return RiskAssessment(
            level=level,
            score=score,
            reasons=reasons,
            recommendation=rec,
            suggested_profile=suggested,
            allow_download_original=True,
            allow_sanitization=True
        )
