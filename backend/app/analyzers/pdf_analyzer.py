import re
from pathlib import Path
from typing import Dict, Any, List, Set, Optional
from app.analyzers.base import BaseAnalyzer, AnalyzerResult, Finding, extract_clean_urls
from app.analyzers.didier_pdf import DidierPDFAnalyzer
from app.core.settings_store import settings_store
from app.core.logging_config import logger
import fitz

COMMON_MALWARE_PASSWORDS = [
    "infected", "virus", "password", "123456", "malware", "clean",
    "sample", "test", "1234", "rules", "danger"
]

class PDFAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "PDFAnalyzer"

    def analyze(self, file_path: Path, filename: str, mime_type: str, provided_password: Optional[str] = None) -> AnalyzerResult:
        findings: List[Finding] = []
        urls: Set[str] = set()
        data: Dict[str, Any] = {}

        try:
            doc = fitz.open(file_path)
        except Exception as e:
            return AnalyzerResult(
                analyzer_name=self.name,
                success=False,
                error_message=f"Failed to parse PDF document: {e}",
                findings=[Finding(
                    category="structure",
                    severity="high",
                    title="Malformed PDF Document",
                    description=f"PDF parser failed to process file structure: {e}"
                )],
                data={}
            )

        try:
            is_encrypted = doc.is_encrypted
            is_unlocked = False
            unlocked_with_pwd = None

            if is_encrypted:
                # 1. Try empty password
                if doc.authenticate("") > 0:
                    is_unlocked = True
                else:
                    candidates = []
                    if provided_password:
                        candidates.append(provided_password)
                    candidates.extend(COMMON_MALWARE_PASSWORDS)

                    for cand in candidates:
                        try:
                            if doc.authenticate(cand) > 0:
                                is_unlocked = True
                                unlocked_with_pwd = cand
                                break
                        except Exception:
                            pass

                if is_unlocked:
                    # Save decrypted PDF back to file_path for downstream OCR / YARA / ClamAV
                    try:
                        doc.save(str(file_path), encryption=fitz.PDF_ENCRYPT_NONE)
                        # Re-open the newly decrypted doc
                        doc.close()
                        doc = fitz.open(file_path)
                    except Exception as e:
                        logger.debug(f"Could not re-save decrypted PDF: {e}")

                    findings.append(Finding(
                        category="structure",
                        severity="low",
                        title="Password-Protected Document Successfully Decrypted",
                        description=(
                            f"The PDF was encrypted and was successfully unlocked with password '{unlocked_with_pwd}'. "
                            "Content was decrypted for in-depth security inspection."
                        ),
                        details={"password": unlocked_with_pwd, "method": "user_supplied" if unlocked_with_pwd == provided_password else "dictionary_attack"}
                    ))
                else:
                    findings.append(Finding(
                        category="structure",
                        severity="high",
                        title="Password-Protected / Encrypted PDF (Locked)",
                        description=(
                            "The document is password-protected and could not be unlocked with common passwords. "
                            "Deep content inspection is restricted. Enter the password in the dashboard to unlock analysis."
                        ),
                        details={"is_encrypted": True}
                    ))

            data["is_password_protected"] = is_encrypted
            data["is_unlocked"] = is_unlocked
            data["unlock_password"] = unlocked_with_pwd

            page_count = doc.page_count
            metadata = doc.metadata or {}

            # Run Didier Stevens PDFiD & stream analyzer
            didier_res = DidierPDFAnalyzer.scan_file(file_path)

            # Read raw content for low-level structural tokens and exploit indicators
            with open(file_path, "rb") as f:
                raw_bytes = f.read()

            raw_text = raw_bytes.decode('latin-1', errors='ignore')

            # 1. Structural tokens check (augmented by Didier Stevens PDFiD)
            has_js = didier_res.get("has_javascript", False) or bool(re.search(r'/(?:JavaScript|JS)\b', raw_text))
            has_launch = didier_res.get("has_launch", False) or bool(re.search(r'/Launch\b', raw_text))
            has_open_action = didier_res.get("has_automatic_action", False) or bool(re.search(r'/OpenAction\b', raw_text))
            emb_count = 0
            if not is_encrypted or is_unlocked:
                try:
                    emb_count = doc.embfile_count()
                except Exception:
                    emb_count = 0

            has_embedded_files = (didier_res.get("pdfid_counts", {}).get("/EmbeddedFiles", 0) > 0) or bool(re.search(r'/(?:EmbeddedFiles|EF)\b', raw_text)) or emb_count > 0
            has_acroform = (didier_res.get("pdfid_counts", {}).get("/AcroForm", 0) > 0) or bool(re.search(r'/AcroForm\b', raw_text))
            has_xfa = (didier_res.get("pdfid_counts", {}).get("/XFA", 0) > 0) or bool(re.search(r'/XFA\b', raw_text))
            has_richmedia = (didier_res.get("pdfid_counts", {}).get("/RichMedia", 0) > 0) or bool(re.search(r'/(?:RichMedia|Screen|Movie)\b', raw_text))

            # Incremental updates check (count of %%EOF markers)
            eof_count = len(re.findall(r'%%EOF', raw_text))

            # 2. Extract Embedded Files Details
            embedded_files_list = []
            if not is_encrypted or is_unlocked:
                try:
                    for i in range(emb_count):
                        info = doc.embfile_info(i)
                        embedded_files_list.append(info.get("filename", f"attachment_{i}"))
                except Exception:
                    pass

            # 3. Extract Links, Annotations, and Embedded Images from pages
            annot_count = 0
            image_count = 0
            page_texts = []
            detected_qr_codes = []
            if not is_encrypted or is_unlocked:
                try:
                    for page_idx, page in enumerate(doc):
                        try:
                            # Page links
                            links = page.get_links()
                            for link in links:
                                uri = link.get("uri")
                                if uri:
                                    urls.add(uri)
                            # Page annots
                            annots = list(page.annots())
                            annot_count += len(annots)
                            # Page embedded images
                            page_images = page.get_images()
                            image_count += len(page_images)
                            for img_info in page_images:
                                xref = img_info[0]
                                try:
                                    extracted_img = doc.extract_image(xref)
                                    if extracted_img and "image" in extracted_img:
                                        raw_img_data = extracted_img["image"]
                                        # Search for clean URLs embedded in image metadata or text chunks
                                        urls.update(extract_clean_urls(raw_img_data.decode('latin-1', errors='ignore')))
                                        try:
                                            from app.analyzers.qr_scanner import QRScanner
                                            qrs = QRScanner.scan_image_bytes(raw_img_data, f"Page {page_idx + 1} Image (xref {xref})")
                                            if qrs:
                                                detected_qr_codes.extend(qrs)
                                                for q in qrs:
                                                    if q.get("url"):
                                                        urls.add(q["url"])
                                        except Exception:
                                            pass
                                except Exception:
                                    pass

                            # Scan rendered page canvas for vector-drawn or inline QR barcodes (first 5 pages)
                            if page_idx < 5 and not any(q.get("source", "").startswith(f"Page {page_idx + 1}") for q in detected_qr_codes):
                                try:
                                    from app.analyzers.qr_scanner import QRScanner
                                    pix = page.get_pixmap(dpi=150)
                                    pix_bytes = pix.tobytes("png")
                                    qrs = QRScanner.scan_image_bytes(pix_bytes, f"PDF Page {page_idx + 1} Canvas")
                                    if qrs:
                                        detected_qr_codes.extend(qrs)
                                        for q in qrs:
                                            if q.get("url"):
                                                urls.add(q["url"])
                                except Exception:
                                    pass

                            # Extract text & text URLs
                            page_text = page.get_text()
                            page_texts.append(page_text)
                            urls.update(extract_clean_urls(page_text))
                        except Exception:
                            pass
                except Exception:
                    pass

            # Also find raw URI actions in PDF bytes
            for raw_uri in re.findall(r'/URI\s*\(([^)]+)\)', raw_text):
                urls.update(extract_clean_urls(raw_uri))

            # Also extract URLs embedded within document metadata
            if metadata:
                for m_val in metadata.values():
                    if m_val and isinstance(m_val, str):
                        urls.update(extract_clean_urls(m_val))

            # 4. Enumerate Full Object & Stream Table (PDF Internals)
            pdf_objects = []
            filter_counts = {}
            stream_count = 0
            obj_count = 0

            try:
                xref_len = doc.xref_length()
                obj_count = max(0, xref_len - 1)
                for xref in range(1, min(xref_len, 400)):
                    try:
                        is_stream = doc.xref_is_stream(xref)
                        if is_stream:
                            stream_count += 1

                        obj_type = ""
                        try:
                            t_key = doc.xref_get_key(xref, "Type")
                            if t_key and t_key[0] == "name":
                                obj_type = t_key[1]
                            elif not obj_type:
                                st_key = doc.xref_get_key(xref, "Subtype")
                                if st_key and st_key[0] == "name":
                                    obj_type = st_key[1]
                        except Exception:
                            pass

                        filter_name = ""
                        try:
                            f_key = doc.xref_get_key(xref, "Filter")
                            if f_key and f_key[0] in ["name", "array"]:
                                filter_name = str(f_key[1])
                                filter_counts[filter_name] = filter_counts.get(filter_name, 0) + 1
                        except Exception:
                            pass

                        size = 0
                        is_suspicious = False
                        suspicious_reason = ""

                        if is_stream:
                            try:
                                stream_bytes = doc.xref_stream(xref)
                                size = len(stream_bytes) if stream_bytes else 0
                                if stream_bytes:
                                    s_low = stream_bytes[:512].lower()
                                    if b"/javascript" in s_low or b"unescape" in s_low or b"eval(" in s_low:
                                        is_suspicious = True
                                        suspicious_reason = "Embedded JavaScript actions"
                                    elif b"/launch" in s_low:
                                        is_suspicious = True
                                        suspicious_reason = "Operating system launch action"
                                    elif b"powershell" in s_low or b"cmd.exe" in s_low:
                                        is_suspicious = True
                                        suspicious_reason = "Shellcode command execution strings"
                            except Exception:
                                pass

                        pdf_objects.append({
                            "xref": xref,
                            "type": obj_type or ("Stream" if is_stream else "Dictionary / Object"),
                            "is_stream": is_stream,
                            "filter": filter_name or "Plaintext",
                            "size": size,
                            "is_suspicious": is_suspicious,
                            "suspicious_reason": suspicious_reason
                        })
                    except Exception:
                        pass
            except Exception as xe:
                logger.debug(f"PDF xref enumeration note: {xe}")

            # 5. Generate Security Findings
            if has_launch:
                findings.append(Finding(
                    category="structure",
                    severity="critical",
                    title="Suspicious /Launch Action Detected",
                    description=(
                        "The document contains a /Launch action. Launch actions can trigger local command "
                        "execution or launch external programs, posing a severe exploit risk."
                    )
                ))

            if has_js:
                findings.append(Finding(
                    category="javascript",
                    severity="high",
                    title="JavaScript Detected in PDF",
                    description=(
                        "Active JavaScript was discovered within PDF objects or actions. "
                        "JavaScript in PDFs is frequently abused for heap-spraying, sandbox escapes, or phishing."
                    )
                ))

            if has_open_action:
                findings.append(Finding(
                    category="structure",
                    severity="medium",
                    title="Automatic /OpenAction Trigger Detected",
                    description="The document specifies an action that runs automatically upon opening."
                ))

            if has_embedded_files:
                findings.append(Finding(
                    category="structure",
                    severity="high",
                    title="Embedded Files / Attachments Detected",
                    description=f"PDF contains {len(embedded_files_list) or 'one or more'} embedded file attachments.",
                    details={"files": embedded_files_list}
                ))

            if has_xfa:
                findings.append(Finding(
                    category="structure",
                    severity="high",
                    title="XML Forms Architecture (XFA) Detected",
                    description=(
                        "Document contains dynamic XFA forms. XFA has historically been a significant "
                        "vector for remote code execution vulnerabilities in PDF readers."
                    )
                ))
            elif has_acroform:
                findings.append(Finding(
                    category="structure",
                    severity="low",
                    title="Interactive AcroForm Detected",
                    description="Document contains interactive form fields."
                ))

            if has_richmedia:
                findings.append(Finding(
                    category="structure",
                    severity="medium",
                    title="Embedded Media Objects Detected",
                    description="Document contains embedded rich media, screen, or movie annotations."
                ))

            if eof_count > 1:
                findings.append(Finding(
                    category="structure",
                    severity="low",
                    title=f"Multiple Incremental Updates ({eof_count} revisions)",
                    description=(
                        "Document contains multiple incremental updates (revisions). "
                        "Incremental updates can mask previous content modifications or shadow attacks."
                    ),
                    details={"revision_count": eof_count}
                ))

            meta_count = sum(1 for v in metadata.values() if v)
            if meta_count > 0:
                findings.append(Finding(
                    category="metadata",
                    severity="low",
                    title=f"Document Metadata Present ({meta_count} fields)",
                    description=f"PDF contains author, creator, or timestamp metadata.",
                    details=metadata
                ))

            if urls:
                findings.append(Finding(
                    category="url",
                    severity="medium" if len(urls) > 5 else "low",
                    title=f"{len(urls)} External URL(s) Discovered in PDF",
                    description=f"Discovered {len(urls)} external links across document pages and stream actions.",
                    details={"urls": list(urls)[:20]}
                ))

            if didier_res.get("has_hex_obfuscation"):
                findings.append(Finding(
                    category="structure",
                    severity="high",
                    title="Obfuscated PDF Token Names Detected (Didier Stevens PDFiD)",
                    description=(
                        "Document utilizes hex-encoded character escapes (e.g. /#4a#61vaScript or /L#61unch) "
                        "in PDF names. Malware commonly employs hex token obfuscation to defeat naive signature scanners."
                    ),
                    details={"obfuscated_tags": didier_res.get("obfuscated_tags", {})}
                ))

            if image_count > 0:
                findings.append(Finding(
                    category="structure",
                    severity="info",
                    title=f"Embedded Raster Images Detected ({image_count})",
                    description=f"PDF document contains {image_count} embedded raster graphic/image objects.",
                    details={"image_count": image_count}
                ))

            didier_counts = didier_res.get("pdfid_counts", {})

            data = {
                "page_count": page_count,
                "image_count": image_count,
                "is_encrypted": is_encrypted,
                "is_password_protected": is_encrypted,
                "is_unlocked": is_unlocked,
                "unlock_password": unlocked_with_pwd,
                "metadata": metadata,
                "has_javascript": has_js,
                "has_launch_action": has_launch,
                "has_open_action": has_open_action,
                "has_embedded_files": has_embedded_files,
                "embedded_files": embedded_files_list,
                "has_acroform": has_acroform,
                "has_xfa": has_xfa,
                "has_richmedia": has_richmedia,
                "annotation_count": annot_count,
                "incremental_updates": eof_count,
                "urls": list(urls),
                "pdfid": didier_counts,
                "pdfid_counts": didier_counts,
                "pdfid_tags": didier_counts,
                "obfuscated_tags": didier_res.get("obfuscated_tags", {}),
                "pdf_objects": pdf_objects,
                "total_objects": obj_count,
                "total_streams": stream_count,
                "filter_counts": filter_counts,
                "pdf_version": metadata.get("format", "PDF"),
                "is_linearized": bool(re.search(r'/Linearized\b', raw_text)),
                "text": "\n".join(page_texts)
            }

            if has_js and didier_res.get("combined_js_code"):
                data["extracted_code"] = {
                    "type": "javascript",
                    "language": "javascript",
                    "code": didier_res["combined_js_code"],
                    "modules": didier_res.get("extracted_js_modules", [])
                }


            if detected_qr_codes:
                try:
                    from app.analyzers.qr_scanner import QRScanner
                    findings.extend(QRScanner.generate_findings(detected_qr_codes, "PDF Document"))
                    data["qr_codes"] = detected_qr_codes
                except Exception as qr_gen_err:
                    logger.debug(f"QR findings generation error: {qr_gen_err}")

            return AnalyzerResult(
                analyzer_name=self.name,
                success=True,
                findings=findings,
                data=data
            )
        finally:
            doc.close()
