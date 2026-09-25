from abc import ABC, abstractmethod
from typing import Dict, Any, List
from pathlib import Path
from pydantic import BaseModel, Field

class Finding(BaseModel):
    category: str  # e.g., "malware", "macro", "javascript", "metadata", "url", "archive", "structure"
    severity: str  # "info", "low", "medium", "high", "critical"
    title: str
    description: str
    details: Dict[str, Any] = Field(default_factory=dict)

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
