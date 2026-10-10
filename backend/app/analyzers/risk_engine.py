from typing import List, Dict, Any, Tuple, Optional
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
    breakdown: List[Dict[str, Any]] = Field(default_factory=list)
    calculation_formula: Optional[str] = None

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
        breakdown: List[Dict[str, Any]] = []

        # 1. Check for Active Malware (Definite Malicious Signature)
        if clamav_status == "MALICIOUS":
            for f in findings:
                if f.category == "malware" and f.severity == "critical":
                    reasons.append(f"⚠ {f.title}")
                    breakdown.append({
                        "factor": f.title,
                        "category": "malware",
                        "subscore": 100,
                        "reason": f.description or "Active malware signature match"
                    })
            if not breakdown:
                breakdown.append({
                    "factor": "Antivirus Signature Match (ClamAV)",
                    "category": "malware",
                    "subscore": 100,
                    "reason": "Antivirus engine matched a verified malicious file signature"
                })
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
                allow_sanitization=False,
                breakdown=breakdown,
                calculation_formula="Direct Malicious Verdict: Threat score locked at 100/100 (Critical Quarantine Policy)"
            )

        # 2. Structural & Exploit Indicators
        critical_reasons = []
        high_reasons = []
        medium_reasons = []
        low_reasons = []

        base_score = 0
        if has_path_traversal:
            critical_reasons.append("⚠ Archive contains path traversal entries (..)")
            base_score += 45
            breakdown.append({
                "factor": "Path Traversal Anomaly (..)",
                "category": "structure",
                "subscore": 45,
                "reason": "Archive contains relative directory traversal paths designed to escape sandbox bounds"
            })

        if is_zip_bomb:
            critical_reasons.append("⚠ Archive exhibits zip-bomb characteristics (excessive size/files)")
            base_score += 45
            breakdown.append({
                "factor": "Decompression Bomb / Zip Bomb",
                "category": "structure",
                "subscore": 45,
                "reason": "Excessive compression ratio indicating resource exhaustion / denial-of-service attempt"
            })

        if has_executable:
            critical_reasons.append("⚠ Contains executable binaries or system scripts")
            base_score += 35
            breakdown.append({
                "factor": "Embedded Executables or Scripts",
                "category": "embedded",
                "subscore": 35,
                "reason": "Contains nested binary executables, dynamic scripts, or installer payloads"
            })

        if has_macros:
            critical_reasons.append("⚠ Visual Basic for Applications (VBA) macros detected")
            base_score += 40
            breakdown.append({
                "factor": "VBA Macro Storage",
                "category": "macro",
                "subscore": 40,
                "reason": "Office document contains embedded VBA macro streams and code modules"
            })

        if has_javascript and category in ["pdf", "office"]:
            critical_reasons.append(f"⚠ Executable JavaScript actions detected in {category.upper()} document")
            base_score += 35
            breakdown.append({
                "factor": f"{category.upper()} Embedded JavaScript",
                "category": "javascript",
                "subscore": 35,
                "reason": f"Active JavaScript actions or interactive scripts found within {category.upper()}"
            })

        if is_mismatch:
            high_reasons.append("⚠ MIME type / file extension spoofing detected")
            base_score += 15
            breakdown.append({
                "factor": "MIME Type Spoofing / Extension Mismatch",
                "category": "structure",
                "subscore": 15,
                "reason": "Declared file extension mismatches true magic bytes and binary payload header"
            })

        # 3. Categorized Findings Scoring (avoiding double counting and runaway accumulation)
        findings_score = 0
        metadata_score = 0
        url_score = 0
        general_score = 0

        for f in findings:
            cat = (f.category or "").lower()
            sev = (f.severity or "low").lower()
            title = f.title.strip()
            reason_text = f"⚠ {title}" if sev in ["critical", "high"] else f"• {title}"

            if cat == "metadata":
                # Metadata tags should never inflate risk into high or malicious
                if sev == "high":
                    sub = 15
                    metadata_score = max(metadata_score, sub)
                    high_reasons.append(reason_text)
                elif sev == "medium":
                    sub = 10
                    metadata_score = max(metadata_score, sub)
                    medium_reasons.append(reason_text)
                else:
                    sub = 5
                    metadata_score = max(metadata_score, sub)
                    low_reasons.append(reason_text)
                breakdown.append({
                    "factor": f"Metadata: {title}",
                    "category": "metadata",
                    "subscore": sub,
                    "reason": f.description or "Document metadata tag exposure"
                })
            elif cat == "url":
                if sev == "critical":
                    sub = 35
                    url_score += sub
                    critical_reasons.append(reason_text)
                elif sev == "high":
                    sub = 20
                    url_score += sub
                    high_reasons.append(reason_text)
                elif sev == "medium":
                    sub = 8
                    url_score += sub
                    medium_reasons.append(reason_text)
                else:
                    sub = 2
                    url_score += sub
                breakdown.append({
                    "factor": f"URL/Domain: {title}",
                    "category": "url",
                    "subscore": sub,
                    "reason": f.description or "Discovered external URL or reputation hit"
                })
            elif cat in ["macro", "javascript", "active_content"]:
                # If already flagged by has_macros / has_javascript, add nuance if severe
                if sev == "critical":
                    sub = 25
                    general_score += sub
                    critical_reasons.append(reason_text)
                elif sev == "high":
                    sub = 15
                    general_score += sub
                    high_reasons.append(reason_text)
                else:
                    sub = 5
                    general_score += sub
                    medium_reasons.append(reason_text)
                breakdown.append({
                    "factor": f"Active Content: {title}",
                    "category": cat,
                    "subscore": sub,
                    "reason": f.description or "Active content or executable script construct"
                })
            elif cat in ["yara", "watchlist", "malware"]:
                if sev == "critical":
                    sub = 45
                    general_score += sub
                    critical_reasons.append(reason_text)
                elif sev == "high":
                    sub = 25
                    general_score += sub
                    high_reasons.append(reason_text)
                elif sev == "medium":
                    sub = 12
                    general_score += sub
                    medium_reasons.append(reason_text)
                else:
                    sub = 3
                    general_score += sub
                    low_reasons.append(reason_text)
                breakdown.append({
                    "factor": f"Security Rule: {title}",
                    "category": cat,
                    "subscore": sub,
                    "reason": f.description or "YARA rule, watchlist, or threat intelligence marker"
                })
            else:
                if sev == "critical":
                    sub = 30
                    general_score += sub
                    critical_reasons.append(reason_text)
                elif sev == "high":
                    sub = 18
                    general_score += sub
                    high_reasons.append(reason_text)
                elif sev == "medium":
                    sub = 8
                    general_score += sub
                    medium_reasons.append(reason_text)
                else:
                    sub = 2
                    general_score += sub
                    low_reasons.append(reason_text)
                breakdown.append({
                    "factor": f"Heuristic: {title}",
                    "category": cat or "heuristic",
                    "subscore": sub,
                    "reason": f.description or "Static heuristic or forensic anomaly"
                })

        # Cap sub-scores to maintain realistic bounds
        metadata_score = min(metadata_score, 20)
        url_score = min(url_score, 45)
        findings_score = metadata_score + url_score + general_score

        raw_total_score = base_score + findings_score
        total_score = raw_total_score

        # Deduplicate reasons while preserving priority order
        seen = set()
        deduped_reasons = []
        for r in critical_reasons + high_reasons + medium_reasons + low_reasons:
            clean_r = r.strip()
            if clean_r not in seen:
                seen.add(clean_r)
                deduped_reasons.append(clean_r)

        # 4. Determine Level and Recommendations
        if total_score >= 65 or critical_reasons:
            level = "HIGH RISK"
            total_score = max(total_score, 65)
            rec = (
                "The file contains active executable content, structural anomalies, or dangerous references. "
                "Do not distribute the original file. Use Maximum Sanitization (Content Disarm and Reconstruction) "
                "to strip all active code before sharing."
            )
            suggested = "maximum"
            reasons = deduped_reasons[:6] if deduped_reasons else ["⚠ High-risk structural indicators detected"]

        elif total_score >= 25 or high_reasons or (medium_reasons and len(medium_reasons) >= 2):
            level = "MEDIUM RISK"
            total_score = max(min(total_score, 64), 25)
            rec = (
                "The file contains embedded external resources, sensitive metadata (e.g. GPS), or interactive elements. "
                "Recommended action: Use Security or Privacy Sanitization."
            )
            suggested = "security"
            reasons = (high_reasons + medium_reasons)[:5] if (high_reasons or medium_reasons) else deduped_reasons[:5]

        elif total_score > 0 or deduped_reasons:
            level = "LOW RISK"
            total_score = max(min(total_score, 24), 5)
            rec = (
                "The file contains no detected active content or suspicious embedded objects. "
                "Recommended action: Remove metadata before sharing."
            )
            suggested = "privacy"
            reasons = (medium_reasons + low_reasons)[:4] if (medium_reasons or low_reasons) else ["• Minor metadata tags present"]

        else:
            level = "CLEAN"
            total_score = 0
            rec = (
                "No active content, suspicious URLs, or sensitive metadata detected. "
                "The file appears clean under current scanner heuristics."
            )
            suggested = "minimal"
            reasons = ["✓ No threats, active code, or sensitive tags detected"]

        # Cap score at 99 (100 is strictly reserved for confirmed malware)
        total_score = min(total_score, 99)

        formula = f"Base Structure ({base_score}) + Metadata ({metadata_score}) + URLs ({url_score}) + Static Scanners ({general_score}) = Raw ({raw_total_score}) → Calibrated Score: {total_score}/100"

        return RiskAssessment(
            level=level,
            score=total_score,
            reasons=reasons,
            recommendation=rec,
            suggested_profile=suggested,
            allow_download_original=True,
            allow_sanitization=True,
            breakdown=breakdown,
            calculation_formula=formula
        )

