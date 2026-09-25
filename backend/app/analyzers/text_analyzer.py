import re
from pathlib import Path
from typing import Dict, Any, List, Set
from app.analyzers.base import BaseAnalyzer, AnalyzerResult, Finding

URL_REGEX = re.compile(
    r'(?:https?|ftp)://[a-zA-Z0-9\-\._~:/\?#\[\]@!\$&\'\(\)\*\+,;=%]+',
    re.IGNORECASE
)

# CSV Formula Injection indicators (DDE attacks)
CSV_FORMULA_INJECTION_RE = re.compile(r'^[=+\-@\t\r].*?(?:cmd|powershell|mshta|regsvr32|rundll32|cscript|wscript)', re.IGNORECASE | re.MULTILINE)

class TextAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "TextAnalyzer"

    def analyze(self, file_path: Path, filename: str, mime_type: str) -> AnalyzerResult:
        findings: List[Finding] = []
        urls: Set[str] = set()
        data: Dict[str, Any] = {
            "encoding": "unknown",
            "has_bom": False,
            "line_count": 0,
            "has_suspicious_patterns": False,
            "has_csv_injection": False,
            "urls": []
        }

        # 1. Detect Encoding
        raw_bytes = file_path.read_bytes()
        encoding = "utf-8"
        has_bom = False

        if raw_bytes.startswith(b"\xef\xbb\xbf"):
            encoding = "utf-8-sig"
            has_bom = True
        elif raw_bytes.startswith(b"\xff\xfe"):
            encoding = "utf-16-le"
            has_bom = True
        elif raw_bytes.startswith(b"\xfe\xff"):
            encoding = "utf-16-be"
            has_bom = True

        data["has_bom"] = has_bom

        try:
            text = raw_bytes.decode(encoding, errors="replace")
            data["encoding"] = encoding
        except Exception:
            text = raw_bytes.decode("latin-1", errors="replace")
            data["encoding"] = "latin-1"

        data["line_count"] = text.count("\n") + 1

        # 2. Extract URLs
        for u in URL_REGEX.findall(text):
            urls.add(u)

        if urls:
            findings.append(Finding(
                category="url",
                severity="low",
                title=f"Extracted URLs ({len(urls)})",
                description="URLs discovered within text body.",
                details={"urls": list(urls)[:20]}
            ))

        # 3. Check CSV Formula Injection (DDE)
        is_csv = filename.lower().endswith(".csv") or mime_type == "text/csv"
        if is_csv:
            matches = CSV_FORMULA_INJECTION_RE.findall(text)
            if matches:
                data["has_csv_injection"] = True
                findings.append(Finding(
                    category="structure",
                    severity="high",
                    title="CSV / Spreadsheet Formula Injection Detected",
                    description=(
                        "CSV contains cell values starting with formula prefixes (=, +, -, @) executing system binaries. "
                        "When opened in Microsoft Excel, these cells can trigger remote command execution."
                    ),
                    details={"matched_formulas": matches[:5]}
                ))

        # 4. Check for hidden or suspicious scripts in plain text files
        if "<script" in text.lower():
            findings.append(Finding(
                category="javascript",
                severity="medium",
                title="HTML Script Tags in Text Content",
                description="File contains embedded HTML <script> tags."
            ))

        data["urls"] = list(urls)

        return AnalyzerResult(
            analyzer_name=self.name,
            success=True,
            findings=findings,
            data=data
        )
