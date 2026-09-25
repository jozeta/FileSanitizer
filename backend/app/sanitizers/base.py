from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class SanitizationOptions(BaseModel):
    profile: Optional[str] = "privacy"  # "minimal", "privacy", "security", "maximum", "custom"

    # General / Metadata
    remove_metadata: bool = True
    remove_gps: bool = True
    remove_author: bool = True
    remove_timestamps: bool = True
    remove_comments: bool = True

    # Active Content & Danger Removal
    remove_embedded_files: bool = True
    remove_macros: bool = True
    remove_javascript: bool = True
    remove_external_links: bool = True
    remove_hyperlinks: bool = False

    # Image Specific
    reencode_image: bool = True
    flatten_image: bool = False
    convert_to_jpg: bool = False
    convert_to_png: bool = False

    # PDF / Document CDR
    flatten_document: bool = False
    rasterize_pages: bool = False  # Max CDR: render pages -> images -> new document
    convert_to_pdf: bool = False

    # SVG / HTML
    strip_active_content: bool = True
    strip_external_resources: bool = True

class SanitizationResult(BaseModel):
    success: bool
    output_path: Path
    sanitized_filename: str
    target_extension: str
    removed_items: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)

class BaseSanitizer(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def sanitize(
        self,
        input_path: Path,
        output_path: Path,
        options: SanitizationOptions,
        original_filename: str
    ) -> SanitizationResult:
        pass
