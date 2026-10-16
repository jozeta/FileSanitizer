import re
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Set
from pathlib import Path
from pydantic import BaseModel, Field, field_validator

URL_REGEX = re.compile(
    r'(?:https?|ftp)://[a-zA-Z0-9\-\._~:/\?#\[\]@!\$&\'\(\)\*\+,;=%]+',
    re.IGNORECASE
)

IGNORED_SCHEMAS = (
    "http://schemas.openxmlformats.org/",
    "http://schemas.microsoft.com/",
    "http://purl.org/dc/",
    "http://www.w3.org/",
    "http://ns.adobe.com/",
    "http://xml.apache.org/",
)

def extract_clean_urls(text: str) -> Set[str]:
    """Extract URLs from text, stripping trailing punctuation and filtering XML schema namespaces."""
    found: Set[str] = set()
    if not text:
        return found
    for match in URL_REGEX.findall(text):
        cleaned = re.sub(r'[\)\]\>\.,;:\'"]+$', '', match)
        if cleaned and not any(cleaned.startswith(prefix) for prefix in IGNORED_SCHEMAS):
            found.add(cleaned)
    return found

class Finding(BaseModel):
    category: str  # e.g., "malware", "macro", "javascript", "metadata", "url", "archive", "structure"
    severity: str  # "info", "low", "medium", "high", "critical"
    title: str
    description: str
    details: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, v: str) -> str:
        if isinstance(v, str):
            v_lower = v.lower().strip()
            if v_lower in ("informational", "information"):
                return "info"
            return v_lower
        return v

class AnalyzerResult(BaseModel):
    analyzer_name: str
    success: bool = True
    error_message: str = ""
    findings: List[Finding] = Field(default_factory=list)
    data: Dict[str, Any] = Field(default_factory=dict)

class BaseAnalyzer(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def analyze(self, file_path: Path, filename: str, mime_type: str) -> AnalyzerResult:
        pass
