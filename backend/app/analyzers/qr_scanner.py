"""
Forensic QR Code & Quishing (QR Phishing) Analyzer.
Detects, isolates, and decodes 2D QR matrix barcodes across images, email attachments,
and embedded PDF document images using OpenCV computer vision.

Identifies:
- Quishing attack vectors (credential harvesting lures, fake MFA authenticators)
- Decoded URLs and parameters
- Geometrical bounding boxes
"""

import re
import urllib.parse
from pathlib import Path
from typing import List, Dict, Any, Optional
from app.analyzers.base import Finding, extract_clean_urls
from app.core.logging_config import logger

try:
    import cv2
    import numpy as np
    _CV2_AVAILABLE = True
except ImportError:
    _CV2_AVAILABLE = False
    logger.warning("opencv-python not available: QR code detection disabled")


SUSPICIOUS_QUISHING_KEYWORDS = [
    "login", "signin", "auth", "verify", "account", "mfa", "2fa", "security",
    "password", "update", "credential", "session", "onedrive", "sharepoint",
    "office365", "microsoft", "google", "banking", "payroll", "invoice"
]


class QRScanner:
    """Detects and decodes QR codes embedded in documents and images."""

    @classmethod
    def is_available(cls) -> bool:
        return _CV2_AVAILABLE

    @classmethod
    def scan_image_bytes(cls, img_bytes: bytes, source_label: str = "image") -> List[Dict[str, Any]]:
        """Scan raw image bytes for one or more QR code matrices."""
        if not _CV2_AVAILABLE or not img_bytes:
            return []

        try:
            nparr = np.frombuffer(img_bytes, np.uint8)
            img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            if img is None:
                return []
            return cls._detect_and_decode(img, source_label)
        except Exception as e:
            logger.debug(f"QR scan error on {source_label}: {e}")
            return []

    @classmethod
    def scan_image_file(cls, file_path: Path) -> List[Dict[str, Any]]:
        """Scan an image file on disk for QR codes."""
        if not _CV2_AVAILABLE or not file_path.exists():
            return []

        try:
            img = cv2.imread(str(file_path))
            if img is None:
                return []
            return cls._detect_and_decode(img, file_path.name)
        except Exception as e:
            logger.debug(f"QR scan error on file {file_path}: {e}")
            return []

    @classmethod
    def _detect_and_decode(cls, img: Any, source_label: str) -> List[Dict[str, Any]]:
        detector = cv2.QRCodeDetector()
        results: List[Dict[str, Any]] = []

        try:
            # 1. Try multi-detection
            retval, decoded_info, points, _ = detector.detectAndDecodeMulti(img)
            if retval and decoded_info:
                for idx, text in enumerate(decoded_info):
                    clean_text = (text or "").strip()
                    if clean_text:
                        results.append(cls._build_qr_record(clean_text, source_label, points[idx] if points is not None and idx < len(points) else None))
        except Exception:
            pass

        # 2. Fallback to single detection if multi didn't return anything
        if not results:
            try:
                decoded_text, points, _ = detector.detectAndDecode(img)
                clean_text = (decoded_text or "").strip()
                if clean_text:
                    results.append(cls._build_qr_record(clean_text, source_label, points))
            except Exception:
                pass

        return results

    @classmethod
    def _build_qr_record(cls, text: str, source_label: str, points: Optional[Any] = None) -> Dict[str, Any]:
        extracted_urls = list(extract_clean_urls(text))
        is_url = bool(extracted_urls) or text.lower().startswith(("http://", "https://", "ftp://"))
        primary_url = extracted_urls[0] if extracted_urls else (text if is_url else None)

        is_quishing_suspect = False
        quishing_reasons = []

        if is_url and primary_url:
            p_lower = primary_url.lower()
            matched_keywords = [kw for kw in SUSPICIOUS_QUISHING_KEYWORDS if kw in p_lower]
            if matched_keywords:
                is_quishing_suspect = True
                quishing_reasons.append(f"Decoded destination contains phishing keywords: {', '.join(matched_keywords)}")

            # Check if using URL shortener or IP address
            parsed = urllib.parse.urlparse(primary_url)
            host = parsed.netloc.split(":")[0]
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
                is_quishing_suspect = True
                quishing_reasons.append(f"QR code points directly to numeric IP address destination ({host})")

        return {
            "decoded_text": text,
            "is_url": is_url,
            "url": primary_url,
            "source": source_label,
            "is_quishing_suspect": is_quishing_suspect,
            "quishing_reasons": quishing_reasons,
            "points": points.tolist() if points is not None and hasattr(points, "tolist") else None
        }

    @classmethod
    def generate_findings(cls, qr_results: List[Dict[str, Any]], container_name: str) -> List[Finding]:
        """Convert detected QR codes into security findings."""
        findings: List[Finding] = []
        for qr in qr_results:
            text = qr["decoded_text"]
            is_quishing = qr.get("is_quishing_suspect", False)
            url = qr.get("url")

            if is_quishing:
                findings.append(Finding(
                    category="phishing",
                    severity="critical",
                    title=f"Quishing (QR Phishing) Attack Vector Detected in {container_name}",
                    description=(
                        f"Embedded 2D QR matrix barcode decodes to suspicious destination: '{text}'. "
                        "Quishing is an evasion technique designed to force victims to scan barcodes on unmonitored "
                        "mobile devices, bypassing corporate secure email gateways (SEG) and network security controls."
                    ),
                    details=qr
                ))
            else:
                findings.append(Finding(
                    category="metadata",
                    severity="medium" if qr.get("is_url") else "low",
                    title=f"Embedded QR Code Matrix Detected in {container_name}",
                    description=f"Decoded QR code content: '{text[:150]}...'",
                    details=qr
                ))

        return findings
