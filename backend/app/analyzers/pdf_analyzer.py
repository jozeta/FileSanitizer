import re
from pathlib import Path
from typing import Dict, Any, List, Set, Optional
from app.analyzers.base import BaseAnalyzer, AnalyzerResult, Finding, extract_clean_urls
from app.analyzers.didier_pdf import DidierPDFAnalyzer, PDFID_TAGS
from app.core.settings_store import settings_store
from app.core.logging_config import logger
import fitz
from app.analyzers.pdf_forensics import (
    calculate_shannon_entropy,
    inspect_pdf_structure_and_overlay,
    inspect_digital_signatures,
    inspect_concealed_content,
    inspect_action_chains,
    carve_and_inspect_attachments,
    deobfuscate_and_analyze_javascript,
)


COMMON_MALWARE_PASSWORDS = [
    "infected", "virus", "password", "123456", "malware", "clean",
    "sample", "test", "1234", "rules", "danger"
]


def _format_hex_preview(raw_bytes: bytes, max_len: int = 512) -> str:
    """Formats bytes into standard 16-bytes per line hex offset + hex + ascii dump."""
    lines = []
    chunk = raw_bytes[:max_len]
    for i in range(0, len(chunk), 16):
        block = chunk[i:i+16]
        hex_str = " ".join(f"{b:02x}" for b in block)
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in block)
        lines.append(f"{i:04x}  {hex_str:<48}  |{ascii_str}|")
    return "\n".join(lines)


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
                        doc.close()
                        doc = fitz.open(file_path)
                    except Exception as e:
                        logger.debug(f"Could not re-save decrypted PDF: {e}")

                    findings.append(Finding(
                        category="encryption",
                        severity="low",
                        title=f"Password-Protected Document Successfully Decrypted ({'User Password' if unlocked_with_pwd == provided_password else 'Common Password'})",
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

            # 4. Enumerate Full Object & Stream Table (PDF Internals) with Rich Content Previews
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
                        stream_text = ""
                        stream_hex = ""
                        is_text = False

                        # Read object dictionary / definition
                        raw_dict = ""
                        try:
                            raw_dict = doc.xref_object(xref)
                        except Exception:
                            pass

                        # Detect tokens inside this object
                        found_tokens = []
                        for tag in PDFID_TAGS:
                            if tag in raw_dict:
                                found_tokens.append(tag)

                        entropy = 0.0
                        if is_stream:
                            try:
                                stream_bytes = doc.xref_stream(xref)
                                size = len(stream_bytes) if stream_bytes else 0
                                if stream_bytes:
                                    entropy = calculate_shannon_entropy(stream_bytes)
                                    stream_hex = _format_hex_preview(stream_bytes, max_len=256)
                                    # Attempt text decoding
                                    try:
                                        stream_text = stream_bytes.decode('utf-8')
                                        is_text = True
                                    except UnicodeDecodeError:
                                        try:
                                            stream_text = stream_bytes.decode('latin-1')
                                            # Check if printable
                                            printable = sum(1 for c in stream_text[:200] if 32 <= ord(c) <= 126 or c in '\r\n\t')
                                            is_text = (printable / max(1, min(len(stream_text), 200))) > 0.7
                                        except Exception:
                                            stream_text = ""
                                            is_text = False

                                    # Truncate text preview to 32 KB for performance
                                    if len(stream_text) > 32768:
                                        stream_text = stream_text[:32768] + "\n\n... [Content Truncated - Exceeds 32 KB] ..."

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
                                    elif b"<!entity" in s_low or b"system \"" in s_low:
                                        is_suspicious = True
                                        suspicious_reason = "XML External Entity (XXE) definition"
                                    elif b"post(" in s_low and b"formcalc" in s_low:
                                        is_suspicious = True
                                        suspicious_reason = "FormCalc Post() exfiltration stream"
                                    elif b"c.transform" in s_low or b"fontmatrix" in s_low:
                                        is_suspicious = True
                                        suspicious_reason = "FontMatrix breakout vector (CVE-2024-4367)"
                                    elif entropy > 7.5:
                                        is_suspicious = True
                                        suspicious_reason = f"High Shannon Entropy stream ({entropy:.2f}/8.0 - packed/encrypted)"
                            except Exception:
                                pass

                        pdf_objects.append({
                            "xref": xref,
                            "type": obj_type or ("Stream" if is_stream else "Dictionary / Object"),
                            "is_stream": is_stream,
                            "filter": filter_name or "Plaintext",
                            "size": size,
                            "entropy": entropy,
                            "is_suspicious": is_suspicious,
                            "suspicious_reason": suspicious_reason,
                            "raw_dict": raw_dict,
                            "stream_text": stream_text if is_text else "",
                            "stream_hex": stream_hex,
                            "is_text": is_text,
                            "tokens": found_tokens
                        })
                    except Exception:
                        pass
            except Exception as xe:
                logger.debug(f"PDF xref enumeration note: {xe}")

            # 5. Standard Security Findings
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

            # 6. Deep Exploit, Vulnerability & CVE Detection (Malicious PDF Suite)
            exploit_findings = self._detect_pdf_exploits_and_cves(doc, raw_bytes, raw_text, didier_res)
            findings.extend(exploit_findings)

            # 7. Deep PDF Forensics (Checklist Suite)
            structure_forensics = inspect_pdf_structure_and_overlay(raw_bytes)
            digital_signatures = inspect_digital_signatures(doc, raw_bytes)
            concealed_content = inspect_concealed_content(doc, raw_text)
            action_chains = inspect_action_chains(doc, raw_text)
            carved_attachments = carve_and_inspect_attachments(doc, raw_bytes)

            combined_js = didier_res.get("combined_js_code", "")
            js_analysis = deobfuscate_and_analyze_javascript(combined_js)

            # Overlay Findings
            if structure_forensics.get("has_overlay"):
                findings.append(Finding(
                    category="structure",
                    severity=structure_forensics.get("overlay_threat", "medium"),
                    title=f"Trailing Overlay Data Appended Past %%EOF ({structure_forensics.get('overlay_size')} bytes)",
                    description=(
                        f"Document contains {structure_forensics.get('overlay_size')} bytes of trailing data past the final %%EOF token "
                        f"(Shannon Entropy: {structure_forensics.get('overlay_entropy'):.2f}/8.0). {structure_forensics.get('overlay_desc')}."
                    ),
                    details={
                        "overlay_size": structure_forensics.get("overlay_size"),
                        "overlay_entropy": structure_forensics.get("overlay_entropy"),
                        "overlay_threat": structure_forensics.get("overlay_threat"),
                        "overlay_desc": structure_forensics.get("overlay_desc"),
                        "mitre_technique": "T1027"
                    }
                ))

            # Digital Signatures & Shadow Attacks
            for sig in digital_signatures:
                if sig.get("has_shadow_attack"):
                    findings.append(Finding(
                        category="exploit",
                        severity="critical",
                        title=f"PDF Shadow Attack Detected on Digital Signature (xref {sig.get('xref')})",
                        description=(
                            f"Digital signature by '{sig.get('signer')}' covers byte range up to {sig.get('byte_range')[2] + sig.get('byte_range')[3]} "
                            f"bytes, but file size is {len(raw_bytes)} bytes ({sig.get('shadow_bytes_count')} modified trailing bytes). "
                            "Document was incrementally altered after signing, invalidating document integrity."
                        ),
                        details=sig
                    ))
                else:
                    findings.append(Finding(
                        category="structure",
                        severity="info",
                        title=f"Digital Signature Present: {sig.get('signer')}",
                        description=f"PDF is cryptographically signed ({sig.get('subfilter')}). Reason: {sig.get('reason')}",
                        details=sig
                    ))

            # Concealed Visual Content
            if concealed_content.get("white_text_count", 0) > 0:
                findings.append(Finding(
                    category="evasion",
                    severity="high",
                    title=f"Concealed White-on-White Text Detected ({concealed_content['white_text_count']} span(s))",
                    description=(
                        f"Discovered {concealed_content['white_text_count']} text span(s) rendered with white font color (#FFFFFF) "
                        "against a document page. Concealed text is often utilized for prompt injection attacks, search engine poisoning, or hidden exfiltration instructions."
                    ),
                    details={"samples": concealed_content.get("white_text_spans", [])[:5]}
                ))

            if concealed_content.get("tiny_font_count", 0) > 0:
                findings.append(Finding(
                    category="evasion",
                    severity="medium",
                    title=f"Sub-Pixel Micro Text Detected ({concealed_content['tiny_font_count']} span(s) < 1.0 pt)",
                    description=(
                        f"Discovered {concealed_content['tiny_font_count']} micro-sized text span(s) with font size below 1.0pt. "
                        "Sub-pixel text is invisible to human viewers but parsed by automated scrapers and LLMs."
                    ),
                    details={"samples": concealed_content.get("tiny_font_spans", [])[:5]}
                ))

            if concealed_content.get("off_page_count", 0) > 0:
                findings.append(Finding(
                    category="evasion",
                    severity="medium",
                    title=f"Off-Page Hidden Text Rendering Detected ({concealed_content['off_page_count']} span(s))",
                    description=(
                        f"Document renders {concealed_content['off_page_count']} text element(s) with coordinates outside "
                        "the visible page MediaBox bounding box."
                    ),
                    details={"samples": concealed_content.get("off_page_spans", [])[:5]}
                ))

            if concealed_content.get("has_invisible_render_mode"):
                findings.append(Finding(
                    category="evasion",
                    severity="high",
                    title="Invisible Text Rendering Mode (3 Tr) Detected",
                    description=(
                        "Page content stream declares PDF text rendering operator '3 Tr' (Neither fill nor stroke text). "
                        "Text rendered under mode 3 is rendered invisibly on the canvas while remaining indexable by parsers."
                    )
                ))

            if concealed_content.get("deceptive_link_count", 0) > 0:
                findings.append(Finding(
                    category="phishing",
                    severity="high",
                    title=f"Deceptive Hyperlink Mismatch Detected ({concealed_content['deceptive_link_count']} link(s))",
                    description=(
                        f"Discovered {concealed_content['deceptive_link_count']} hyperlink(s) where the displayed URL text "
                        "points to a completely different domain than the underlying clickable destination URI."
                    ),
                    details={"links": concealed_content.get("deceptive_links", [])[:5], "mitre_technique": "T1566.002"}
                ))

            # Dangerous JavaScript APIs & Shellcode
            if js_analysis.get("dangerous_apis"):
                for api_item in js_analysis["dangerous_apis"]:
                    findings.append(Finding(
                        category="exploit",
                        severity=api_item.get("risk", "high"),
                        title=f"High-Risk Acrobat JavaScript API: {api_item.get('api')}",
                        description=api_item.get("description"),
                        details={"api": api_item.get("api"), "mitre_technique": api_item.get("mitre")}
                    ))

            if js_analysis.get("shellcode_indicators"):
                findings.append(Finding(
                    category="exploit",
                    severity="critical",
                    title="Shellcode / Memory Spray Pattern in PDF JavaScript",
                    description="; ".join(js_analysis["shellcode_indicators"]),
                    details={"indicators": js_analysis["shellcode_indicators"], "mitre_technique": "T1055"}
                ))

            # Carved Attachments Threats
            for att in carved_attachments:
                if att.get("is_threat") or att.get("threat_level") in ["critical", "high"]:
                    findings.append(Finding(
                        category="malware",
                        severity=att.get("threat_level", "critical"),
                        title=f"Weaponized Embedded Attachment: {att.get('filename')} ({att.get('classification')})",
                        description=f"Carved embedded attachment '{att.get('filename')}' ({att.get('size_formatted')}) matches weaponized file classification: {att.get('classification')}.",
                        details=att
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
                "pdfid_token_details": didier_res.get("pdfid_token_details", {}),
                "obfuscated_tags": didier_res.get("obfuscated_tags", {}),
                "obfuscated_samples": didier_res.get("obfuscated_samples", {}),
                "pdf_objects": pdf_objects,
                "total_objects": obj_count,
                "total_streams": stream_count,
                "filter_counts": filter_counts,
                "pdf_version": metadata.get("format", "PDF"),
                "is_linearized": bool(re.search(r'/Linearized\b', raw_text)),
                "text": "\n".join(page_texts),
                "structure_forensics": structure_forensics,
                "digital_signatures": digital_signatures,
                "concealed_content": concealed_content,
                "action_chains": action_chains,
                "carved_attachments": carved_attachments,
                "js_analysis": js_analysis
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

    def _detect_pdf_exploits_and_cves(
        self,
        doc: Any,
        raw_bytes: bytes,
        raw_text: str,
        didier_res: Dict[str, Any]
    ) -> List[Finding]:
        """
        Deep behavioral, exploit, and CVE heuristic detection engine covering the
        entire malicious PDF test matrix (CVE-2018-4993, CVE-2024-4367, PortSwigger vectors, etc.).
        """
        findings: List[Finding] = []

        # 1. CVE-2018-4993 & Forced NTLM Authentication / UNC Path Exfiltration
        # Matches \\host\share in GoToE, GoToR, Thread, URI, Image XObjects, or JS APIs
        unc_matches = re.findall(r'(?i)\\\\[a-zA-Z0-9_\.\-]+(?:\\[^\r\n"\'><)\s]+)?', raw_text)
        has_gotoe = bool(re.search(r'(?i)/GoToE\b', raw_text))
        has_gotor = bool(re.search(r'(?i)/GoToR\b', raw_text))
        has_thread = bool(re.search(r'(?i)/Thread\b', raw_text))
        has_submit_form = bool(re.search(r'(?i)/SubmitForm\b', raw_text))
        has_import_data = bool(re.search(r'(?i)/ImportData\b', raw_text))

        if unc_matches:
            findings.append(Finding(
                category="exploit",
                severity="critical",
                title="Forced NTLM Authentication & UNC Path Exfiltration (CVE-2018-4993)",
                description=(
                    f"Document contains UNC path(s) ({', '.join(set(unc_matches[:3]))}) in PDF action elements, "
                    "FileSpecs, or JavaScript. When opened in vulnerable readers (e.g. Acrobat), this triggers "
                    "automatic SMB negotiation to an external host, leaking NetNTLM authentication hashes."
                ),
                details={"unc_paths": list(set(unc_matches))[:10], "cve": "CVE-2018-4993", "mitre_technique": "T1187"}
            ))
        elif has_gotoe:
            findings.append(Finding(
                category="exploit",
                severity="high",
                title="Remote /GoToE Embedded Action (CVE-2018-4993 Variant)",
                description=(
                    "Document defines a /GoToE (Go To Embedded) action targeting a remote URL or external FileSpec. "
                    "Attackers leverage remote /GoToE actions to trigger unauthorized outbound network requests or NTLM leaks."
                ),
                details={"cve": "CVE-2018-4993", "mitre_technique": "T1187"}
            ))

        # 2. CVE-2024-4367 - PDF.js Arbitrary Code Execution via FontMatrix
        if re.search(r'(?i)/FontMatrix\s*\[[^\]]*(?:eval|Function|c\.transform|c\.scale|\;|\(|\)|[a-zA-Z0-9_\.]+\s*\()[^\]]*\]', raw_text) or \
           re.search(r'/FontMatrix\s*\[\s*\d+\s+\d+\s+\d+\s+\d+\s+\d+\s*\([^)]+\)\s*\]', raw_text):
            findings.append(Finding(
                category="exploit",
                severity="critical",
                title="PDF.js Arbitrary Code Execution via FontMatrix (CVE-2024-4367)",
                description=(
                    "Discovered Type1 font definition with malicious /FontMatrix array containing code execution breakout payloads. "
                    "Exploits CVE-2024-4367 to break out of c.transform() in Mozilla PDF.js and execute arbitrary client-side JavaScript."
                ),
                details={"cve": "CVE-2024-4367", "mitre_technique": "T1059.007"}
            ))

        # 3. CVE-2019-7089 - XFA Remote Stylesheet Injection & UNC Callback
        if re.search(r'(?i)xml-stylesheet[^>]*href=["\'](?:\\\\|https?://)', raw_text):
            findings.append(Finding(
                category="exploit",
                severity="critical",
                title="XFA Remote Stylesheet Injection (CVE-2019-7089)",
                description=(
                    "Dynamic XFA template declares an external xml-stylesheet directive targeting a remote UNC path or URL. "
                    "In vulnerable versions of Adobe Acrobat Reader, this forces unauthenticated NTLM authentication or SSRF."
                ),
                details={"cve": "CVE-2019-7089", "mitre_technique": "T1187"}
            ))

        # 4. CVE-2017-10951 - Foxit Reader this.getURL() Arbitrary Execution
        if re.search(r'(?i)this\.getURL\s*\(', raw_text):
            findings.append(Finding(
                category="exploit",
                severity="high",
                title="Foxit Reader Arbitrary URL Execution (CVE-2017-10951)",
                description=(
                    "JavaScript executes Foxit Reader's this.getURL() API. This function can be abused in Foxit Reader "
                    "to launch external programs, navigate to attacker servers, or execute shell commands without user confirmation."
                ),
                details={"cve": "CVE-2017-10951", "mitre_technique": "T1204"}
            ))

        # 5. CVE-2014-8453 - XFA FormCalc Post() Data Exfiltration & Header Injection
        if re.search(r'(?i)Post\s*\(\s*["\']https?://', raw_text) or (re.search(r'(?i)FormCalc', raw_text) and re.search(r'(?i)\bPost\s*\(', raw_text)):
            findings.append(Finding(
                category="exploit",
                severity="high",
                title="XFA FormCalc Post() Data Exfiltration (CVE-2014-8453)",
                description=(
                    "XFA template contains FormCalc Post() function call. FormCalc allows client-side HTTP POST requests, "
                    "enabling attackers to bypass same-origin policies, exfiltrate form content, or perform blind SSRF."
                ),
                details={"cve": "CVE-2014-8453", "mitre_technique": "T1048"}
            ))

        # 6. XFA Submit HTTP Request / CRLF Header Injection
        if re.search(r'(?i)textEncoding=["\'][^"\']*(?:\r|\n|%0d|%0a)', raw_text) or \
           re.search(r'(?i)<submit[^>]*textEncoding=[^>]*\r?\n', raw_text):
            findings.append(Finding(
                category="exploit",
                severity="high",
                title="XFA Submit HTTP Request / CRLF Header Injection",
                description=(
                    "Form submission event contains CRLF characters in the textEncoding parameter or headers. "
                    "Enables HTTP response splitting, header injection, and unauthorized request tampering."
                ),
                details={"mitre_technique": "T1190"}
            ))

        # 7. XML External Entity (XXE) Injection (CVE-2014-8452, CVE-2016-2175, CVE-2017-9096, CVE-2025-66516)
        if re.search(r'(?i)<!ENTITY[^>]+SYSTEM', raw_text) or \
           re.search(r'(?i)<!DOCTYPE[^>]*\[[^\]]*<!ENTITY', raw_text) or \
           re.search(r'(?i)%[a-zA-Z0-9_\.\-]+;\s*[\'"]', raw_text) or \
           re.search(r'(?i)XMLData\.parse\s*\(', raw_text):
            findings.append(Finding(
                category="exploit",
                severity="critical",
                title="XML External Entity (XXE) Injection in PDF Metadata/XFA (CVE-2016-2175 / CVE-2017-9096)",
                description=(
                    "Discovered external DTD entity declarations (<!ENTITY ... SYSTEM) or parameter entities (%xxe;) "
                    "inside XMP Metadata, AcroForm, or XFA XML streams. Can exfiltrate local files (/etc/passwd, win.ini) "
                    "or trigger Server-Side Request Forgery (SSRF) when processed by Apache PDFBox, iText, or Tika."
                ),
                details={"cve": "CVE-2016-2175", "mitre_technique": "T1190"}
            ))

        # 8. CVE-2018-5158 - PostScript Calculator Function Injection
        if re.search(r'(?i)/FunctionType\s+4\b', raw_text):
            findings.append(Finding(
                category="exploit",
                severity="high",
                title="PostScript Calculator Function Injection (CVE-2018-5158)",
                description=(
                    "Document defines a /FunctionType 4 (PostScript Calculator) function. Historically vulnerable in Mozilla "
                    "PDF.js (CVE-2018-5158) where postscript operator handling permitted arbitrary JavaScript injection."
                ),
                details={"cve": "CVE-2018-5158", "mitre_technique": "T1059"}
            ))

        # 9. CVE-2018-20065 - Silent Background Navigation Without User Gesture
        if re.search(r'(?i)/OpenAction\s*<<[^>]*\/S\s*\/URI', raw_text) or \
           re.search(r'(?i)/OpenAction\s*<<[^>]*\/URI\s*\(', raw_text):
            findings.append(Finding(
                category="exploit",
                severity="high",
                title="Silent Background URL Navigation (CVE-2018-20065)",
                description=(
                    "Document links /OpenAction directly to /S /URI. When rendered in Chromium/PDFium or web viewers, "
                    "this triggers automatic navigation to external websites without requiring user clicks or interaction."
                ),
                details={"cve": "CVE-2018-20065", "mitre_technique": "T1204"}
            ))

        # 10. CVE-2022-28244 - RichMedia Annotation CSP Bypass
        if re.search(r'(?i)/Subtype\s*/RichMedia\b', raw_text) or didier_res.get("pdfid_counts", {}).get("/RichMedia", 0) > 0:
            if re.search(r'(?i)(?:<script|<html|javascript:|flash)', raw_text):
                findings.append(Finding(
                    category="exploit",
                    severity="high",
                    title="RichMedia Annotation Content Security Policy Bypass (CVE-2022-28244)",
                    description=(
                        "RichMedia annotation bundles HTML/JavaScript payloads designed to bypass host application Content "
                        "Security Policies (CSP) and execute unconstrained web scripts."
                    ),
                    details={"cve": "CVE-2022-28244", "mitre_technique": "T1562.001"}
                ))

        # 11. CVE-2020-29075 - Silent Document Lifecycle Tracking Callbacks
        if re.search(r'(?i)/AA\s*<<[^>]*(?:/WC|/WS|/DS)\s*<<[^>]*\/S\s*\/URI', raw_text) or \
           re.search(r'(?i)(?:/WC|/WS|/DS)\s*<<[^>]*\/URI', raw_text):
            findings.append(Finding(
                category="exploit",
                severity="medium",
                title="Silent Document Lifecycle Tracking Callbacks (CVE-2020-29075)",
                description=(
                    "Catalog Additional Actions (/AA) register WillClose (/WC), WillSave (/WS), or DidSave (/DS) events "
                    "to silently contact external servers upon document close or save, tracking reader activity."
                ),
                details={"cve": "CVE-2020-29075", "mitre_technique": "T1071"}
            ))

        # 12. CVE-2025-70401 - PDF Annotation Content Stored XSS
        if re.search(r'(?i)/Subtype\s*/Text[^>]*<img\s+[^>]*src=', raw_text) or \
           re.search(r'(?i)/T\s*\([^)]*<img\s+[^>]*src=[^)]*\)', raw_text):
            findings.append(Finding(
                category="exploit",
                severity="high",
                title="PDF Annotation Stored XSS (CVE-2025-70401)",
                description=(
                    "Text annotation contains raw HTML markup (<img>) in /T or /Contents parameters. "
                    "Exploits web-based PDF viewers (e.g. Apryse WebViewer) to achieve stored cross-site scripting."
                ),
                details={"cve": "CVE-2025-70401", "mitre_technique": "T1059.007"}
            ))

        # 13. CVE-2024-12426 - LibreOffice vnd.sun.star.expand Environment Variable Leak
        if re.search(r'(?i)vnd\.sun\.star\.expand:', raw_text):
            findings.append(Finding(
                category="exploit",
                severity="high",
                title="LibreOffice vnd.sun.star.expand Environment Variable Leak (CVE-2024-12426)",
                description=(
                    "Document uses the 'vnd.sun.star.expand:' URI protocol. In LibreOffice / OpenOffice, this scheme expands "
                    "local environment variables (e.g. ${USER}, ${HOME}, AWS tokens) into the URL and transmits them to attacker servers."
                ),
                details={"cve": "CVE-2024-12426", "mitre_technique": "T1082"}
            ))

        # 14. CVE-2025-59803 - Foxit Signature Detonation via Optional Content Groups
        if re.search(r'(?i)/OCProperties\b', raw_text) and re.search(r'(?i)/AA\s*<<[^>]*(?:/WP|/DP)', raw_text):
            findings.append(Finding(
                category="exploit",
                severity="high",
                title="Foxit Signature Detonation via Optional Content Groups (CVE-2025-59803)",
                description=(
                    "Optional Content Groups (OCG) register WillPrint (/WP) or DidPrint (/DP) triggers within /AA. "
                    "In Foxit Reader, signing a document invokes these actions, allowing code detonation during signature verification."
                ),
                details={"cve": "CVE-2025-59803", "mitre_technique": "T1204"}
            ))

        # 15. CVE-2026-25755 - jsPDF addJS Object Injection
        if re.search(r'(?i)jsPDF', raw_text) and (re.search(r'(?i)addJS', raw_text) or re.search(r'(?i)/AA\s*<<[^>]*\/O\b', raw_text)):
            findings.append(Finding(
                category="exploit",
                severity="high",
                title="jsPDF addJS Object Injection & Auto-Action (CVE-2026-25755)",
                description=(
                    "Document displays signatures of jsPDF addJS() object injection. Malformed object definitions break out of string "
                    "literals to attach automated /AA /O action hooks."
                ),
                details={"cve": "CVE-2026-25755", "mitre_technique": "T1059"}
            ))

        # 16. PortSwigger Advanced Exfiltration & Detonation Vectors
        # A. Action Injection via Parens Delimiter Escape
        if re.search(r'\)[^(\r\n]*\/A\s*<<\s*\/S\s*\/JavaScript', raw_text):
            findings.append(Finding(
                category="exploit",
                severity="critical",
                title="PortSwigger Action Injection via String Delimiter Escape",
                description=(
                    "Unescaped closing parentheses break out of string literals to inject duplicate /A action dictionaries. "
                    "Bypasses sanitization filters by masking JavaScript actions inside benign string parameters."
                ),
                details={"mitre_technique": "T1059"}
            ))

        # B. Auto-Detonating Screen Annotation (/AA /PV)
        if re.search(r'(?i)/PV\s*<<[^>]*\/S\s*\/JavaScript', raw_text):
            findings.append(Finding(
                category="exploit",
                severity="high",
                title="Automatic Page-Visible Screen Action Trigger (/AA /PV)",
                description=(
                    "Screen annotation hooks the /PV (Page Visible) event to detonate JavaScript immediately when the page "
                    "comes into the viewport, bypassing /OpenAction blacklists."
                ),
                details={"mitre_technique": "T1204"}
            ))

        # C. Auto-Detonating Page Close Annotation (/AA /PC)
        if re.search(r'(?i)/PC\s*<<[^>]*\/S\s*\/JavaScript', raw_text):
            findings.append(Finding(
                category="exploit",
                severity="medium",
                title="Automatic Page-Close Action Trigger (/AA /PC)",
                description="Hooks the /PC (Page Close) event to execute JavaScript actions when navigating away from the page."
            ))

        # D. Full PDF Exfiltration via Form Submission (Flags 256 or cSubmitAs: "PDF")
        if re.search(r'(?i)/SubmitForm[^>]*\/Flags\s*256', raw_text) or re.search(r'(?i)cSubmitAs\s*:\s*["\']PDF["\']', raw_text):
            findings.append(Finding(
                category="exploit",
                severity="critical",
                title="Entire PDF Document Exfiltration via Form Submission",
                description=(
                    "Form submission action specifies Flags 256 or cSubmitAs: 'PDF'. This instructs the PDF reader to transmit "
                    "the entire binary PDF document to an external server, leaking confidential document contents."
                ),
                details={"mitre_technique": "T1048"}
            ))

        # E. Invisible Full-Page Button Overlay
        if re.search(r'(?i)/Btn\b', raw_text) and re.search(r'/Rect\s*\[\s*0\s+0\s+(?:595|612|842|792)', raw_text):
            findings.append(Finding(
                category="exploit",
                severity="high",
                title="Invisible Full-Page Button Overlay (Click-Jacking Detonator)",
                description=(
                    "An invisible push-button form widget spans the entire page canvas ([0 0 ...]). Clicking anywhere on the page "
                    "triggers the underlying action, deceiving users into detonating actions."
                ),
                details={"mitre_technique": "T1204"}
            ))

        # F. Blind SSRF Text Field Auto-Submission (/Tx)
        if re.search(r'(?i)/Subtype\s*/Widget[^>]*\/FT\s*/Tx', raw_text) and re.search(r'(?i)submitForm\s*\(', raw_text):
            findings.append(Finding(
                category="exploit",
                severity="high",
                title="Blind SSRF Form Field Auto-Submission Hook",
                description="Form text field (/Tx) automatically executes submitForm() to initiate unauthorized background POST requests."
            ))

        # G. getPageNthWord() Text Harvesting
        if re.search(r'(?i)getPageNthWord\s*\(', raw_text):
            findings.append(Finding(
                category="exploit",
                severity="high",
                title="Document Text Harvesting & Exfiltration (getPageNthWord)",
                description=(
                    "JavaScript executes getPageNthWord() to programmatically scrape rendered text from document pages "
                    "and transmit sensitive contents to an external attacker endpoint."
                ),
                details={"mitre_technique": "T1005"}
            ))

        # H. Mouse-Hover Detonation Hook (/AA /E)
        if re.search(r'(?i)/AA\s*<<[^>]*\/E\s*<<[^>]*\/S\s*\/JavaScript', raw_text) or \
           re.search(r'(?i)/E\s*<<[^>]*\/S\s*\/JavaScript', raw_text):
            findings.append(Finding(
                category="exploit",
                severity="high",
                title="Mouse-Hover JavaScript Detonation Hook (/AA /E)",
                description="Annotation registers an /E (Enter) event handler to detonate JavaScript as soon as the mouse cursor hovers over the element."
            ))

        # I. URL Hijacking via Delimiter Escape
        if re.search(r'\)[^(\r\n]*\/URI\s*\(', raw_text):
            findings.append(Finding(
                category="exploit",
                severity="high",
                title="URL Parameter Hijacking via Delimiter Escape",
                description="Unescaped closing parentheses break out of string context to inject unauthorized /URI navigation targets."
            ))

        # 17. Adobe 0-Day (April 2026) Chained Vectors
        if re.search(r'(?i)RSS\.addFeed\s*\(', raw_text):
            findings.append(Finding(
                category="exploit",
                severity="critical",
                title="Adobe 0-Day RSS.addFeed() Remote Callback Exploit",
                description="JavaScript invokes Acrobat Reader's RSS.addFeed() API to initiate unauthorized background RSS/HTTP callbacks."
            ))

        if re.search(r'(?i)util\.readFileIntoStream', raw_text) and re.search(r'(?i)SOAP\.request', raw_text):
            findings.append(Finding(
                category="exploit",
                severity="critical",
                title="Adobe 0-Day Arbitrary Local File Read & SOAP Exfiltration Chain",
                description=(
                    "Exploit chains Acrobat's util.readFileIntoStream() to read arbitrary local operating system files (/etc/hostname, win.ini) "
                    "and transmits the contents via SOAP.request() to external attacker infrastructure."
                ),
                details={"mitre_technique": "T1005"}
            ))

        if re.search(r'(?i)/Tx\b', raw_text) and re.search(r'/V\s*\([A-Za-z0-9+/=]{40,}\)', raw_text) and \
           re.search(r'(?i)getField\([^)]+\)\.value', raw_text):
            findings.append(Finding(
                category="exploit",
                severity="critical",
                title="Staged Base64 JavaScript Payload in Form Field (Payload Evasion)",
                description=(
                    "Malicious JavaScript payload is staged as base64 ciphertext inside a text form field (/Tx /V) and dynamically "
                    "unpacked at runtime via getField().value to evade static signature scanners."
                ),
                details={"mitre_technique": "T1027"}
            ))

        # 18. Additional Dangerous Actions & Protocols
        if has_gotor and not any(f.title.startswith("Forced NTLM") for f in findings):
            findings.append(Finding(
                category="structure",
                severity="medium",
                title="Remote PDF Document Navigation Action (/GoToR)",
                description="Document contains a /GoToR action referencing external PDF documents on remote servers."
            ))

        if has_submit_form and not any("Exfiltration" in f.title for f in findings):
            findings.append(Finding(
                category="structure",
                severity="medium",
                title="Interactive Form Submission Action (/SubmitForm)",
                description="Document contains a /SubmitForm action configured to submit form data to remote servers."
            ))

        if has_import_data:
            findings.append(Finding(
                category="structure",
                severity="high",
                title="External Data Import Action (/ImportData)",
                description="Document contains an /ImportData action capable of importing remote form data or XML structures into the document."
            ))

        if has_thread and not any(f.title.startswith("Forced NTLM") for f in findings):
            findings.append(Finding(
                category="structure",
                severity="medium",
                title="Silent Article Thread Action (/Thread)",
                description="Document contains a /Thread action that can initiate remote FileSpec connections."
            ))

        if re.search(r'(?i)/FS\s*/URL\b', raw_text):
            findings.append(Finding(
                category="exploit",
                severity="high",
                title="External XObject Stream Silent Page-Render Callback (/FS /URL)",
                description="An XObject stream references an external URL FileSpec (/FS /URL), forcing background HTTP fetch during page rendering."
            ))

        if re.search(r'(?i)/Launch\s*<<[^>]*\/Win\s*<<[^>]*\/O\s*\/print', raw_text):
            findings.append(Finding(
                category="exploit",
                severity="critical",
                title="Remote Execution via Print Launch Action",
                description="The /Launch action invokes the Windows print verb (/O /print) on a remote FileSpec, forcing background execution."
            ))

        # 19. Browser & Acrobat Network APIs
        if re.search(r'(?i)SOAP\.(?:connect|request)\s*\(', raw_text) and not any("0-Day" in f.title for f in findings):
            findings.append(Finding(
                category="exploit",
                severity="high",
                title="Acrobat SOAP Protocol Remote Network Connection",
                description="JavaScript invokes SOAP.connect() or SOAP.request() to perform SOAP-based network callbacks."
            ))

        if re.search(r'(?i)app\.media\.getURLData\s*\(', raw_text):
            findings.append(Finding(
                category="exploit",
                severity="high",
                title="Acrobat Media API Remote Data Fetch",
                description="JavaScript calls app.media.getURLData() to fetch external media streams from remote URLs."
            ))

        if re.search(r'(?i)this\.importDataObject\s*\(', raw_text):
            findings.append(Finding(
                category="exploit",
                severity="high",
                title="Acrobat External Data Object Import Hook",
                description="JavaScript calls this.importDataObject() to import external binary objects into the document."
            ))

        if re.search(r'(?i)\bfetch\s*\(', raw_text):
            findings.append(Finding(
                category="exploit",
                severity="high",
                title="HTML5 Fetch Web API Callback inside PDF Reader",
                description="JavaScript invokes the browser fetch() Web API, indicating an exploit targeting web-based PDF viewers."
            ))

        if re.search(r'(?i)\bXMLHttpRequest\b', raw_text):
            findings.append(Finding(
                category="exploit",
                severity="high",
                title="XMLHttpRequest Background HTTP Request inside PDF Reader",
                description="JavaScript initiates XMLHttpRequest requests to exfiltrate data from web PDF viewers."
            ))

        if re.search(r'(?i)new\s+Image\s*\(\s*\)', raw_text):
            findings.append(Finding(
                category="exploit",
                severity="medium",
                title="Image Beacon Exfiltration Callback inside PDF Reader",
                description="JavaScript instantiates an Image DOM element to trigger a stealthy HTTP GET image beacon callback."
            ))

        if re.search(r'(?i)\bWebSocket\b', raw_text):
            findings.append(Finding(
                category="exploit",
                severity="high",
                title="WebSocket Persistent Channel Callback inside PDF Reader",
                description="JavaScript creates a WebSocket connection, opening a bidirectional communications channel with external C2."
            ))

        # 20. PDF 2.0 Associated Files
        if re.search(r'(?i)/AF\s*\[', raw_text):
            findings.append(Finding(
                category="structure",
                severity="medium",
                title="PDF 2.0 Associated Files Array (/AF) Detected",
                description="Document defines PDF 2.0 Associated Files (/AF) structures which can embed auxiliary HTML, JS, or binary data."
            ))

        # 21. EICAR Antivirus Test Signature
        if b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in raw_bytes:
            findings.append(Finding(
                category="malware",
                severity="critical",
                title="EICAR Standard Antivirus Test Signature Detected",
                description="Document contains the industry-standard inert EICAR antivirus test signature string."
            ))

        # 22. XFA SOAP Submit on Initialize
        if re.search(r'(?i)<event\s+activity=["\']initialize["\']>\s*<submit\s+method=["\']soap["\']', raw_text):
            findings.append(Finding(
                category="exploit",
                severity="critical",
                title="XFA SOAP Form Submission on Document Initialize",
                description="XFA dynamic template registers a SOAP submission event on initialization, triggering automated network requests on document load."
            ))

        # 23. Catalog Names JavaScript Auto-Execution
        if re.search(r'(?i)/Names\s*<<[^>]*\/JavaScript', raw_text):
            findings.append(Finding(
                category="exploit",
                severity="high",
                title="Catalog-Level Name Tree JavaScript Auto-Execution",
                description="Document defines auto-executing scripts registered within the catalog /Names /JavaScript dictionary tree."
            ))

        # 24. Ghostscript Pipe Device & Format String Sandbox Escapes (CVE-2023-36664 / CVE-2024-29510)
        if re.search(r'(?i)(?:%pipe%|\|\s*\/bin\/|\|\s*cmd\.exe|\|\s*powershell|\(\s*%pipe%[^)]+\))', raw_text) or \
           (b"%pipe%" in raw_bytes) or \
           re.search(r'(?i)\/uniprint[^\n\r]*%(?:d%n|[0-9]*[a-zA-Z]%[a-zA-Z])', raw_text):
            findings.append(Finding(
                category="exploit",
                severity="critical",
                title="Ghostscript Pipe Device Command Execution / Format String Sandbox Escape (CVE-2023-36664 / CVE-2024-29510)",
                description=(
                    "PostScript stream contains Ghostscript '%pipe%' device invocation or uniprint format string parameters. "
                    "Exploits CVE-2023-36664 or CVE-2024-29510 to bypass Ghostscript -dSAFER sandbox policies and achieve remote command execution."
                ),
                details={"cve": "CVE-2023-36664", "cve_secondary": "CVE-2024-29510", "mitre_technique": "T1059"}
            ))

        # 25. Adobe Acrobat Out-of-Bounds Write via TrueType Font Bitmap Tables (CVE-2023-26369)
        if re.search(r'(?i)/(?:CIDFontType2|FontFile2|FontFile3)\b', raw_text) and \
           (re.search(r'(?i)\b(?:EBDT|CBLC|bdat|bloc|EBLC)\b', raw_text) or b"EBDT" in raw_bytes or b"CBLC" in raw_bytes):
            findings.append(Finding(
                category="exploit",
                severity="critical",
                title="Adobe Acrobat TrueType Font Table Corruption Exploit (CVE-2023-26369)",
                description=(
                    "Document embeds TrueType/CIDFont streams referencing EBDT/CBLC embedded bitmap tables. "
                    "In vulnerable Adobe Acrobat and Reader versions, malformed bitmap table lengths trigger an out-of-bounds write (CVE-2023-26369) "
                    "leading to arbitrary code execution in the wild."
                ),
                details={"cve": "CVE-2023-26369", "mitre_technique": "T1055"}
            ))

        # 26. JavaScript ES TypedArray Heap Spraying & Use-After-Free (CVE-2021-28550 / CVE-2020-9715)
        if re.search(r'(?i)new\s+(?:Uint8Array|ArrayBuffer|Float64Array|BigUint64Array)\s*\(\s*(?:0x[0-9a-f]{4,}|[0-9]{5,})\s*\)', raw_text) or \
           (re.search(r'(?i)(?:Uint8Array|ArrayBuffer)\b', raw_text) and re.search(r'(?i)(?:while|for)\s*\([^\)]*<[^\)]*(?:100|0x|1000)', raw_text) and re.search(r'(?i)spray\b', raw_text)):
            findings.append(Finding(
                category="exploit",
                severity="critical",
                title="JavaScript TypedArray Heap Spraying & Memory Corruption (CVE-2021-28550 / CVE-2020-9715)",
                description=(
                    "JavaScript allocates multiple large ES TypedArray buffers (Uint8Array/ArrayBuffer/Float64Array) indicative of heap grooming "
                    "and memory spraying. Weaponized in Acrobat Reader zero-days to achieve reliable use-after-free exploitation."
                ),
                details={"cve": "CVE-2021-28550", "mitre_technique": "T1055"}
            ))

        # 27. PDF Polyglot Attack (Prepended ZIP / RAR / PE / HTML Container)
        is_polyglot = False
        poly_type = ""
        if raw_bytes.startswith(b"PK\x03\x04"):
            is_polyglot = True
            poly_type = "ZIP / JAR Archive"
        elif raw_bytes.startswith(b"Rar!\x1a\x07"):
            is_polyglot = True
            poly_type = "RAR Archive"
        elif raw_bytes.startswith(b"MZ"):
            is_polyglot = True
            poly_type = "Windows PE Executable"
        elif raw_bytes.startswith(b"\x7fELF"):
            is_polyglot = True
            poly_type = "Linux ELF Binary"
        elif re.match(rb'^\s*<(!DOCTYPE\s+html|html)', raw_bytes, re.IGNORECASE):
            is_polyglot = True
            poly_type = "HTML / Web Document"

        if is_polyglot:
            findings.append(Finding(
                category="evasion",
                severity="critical",
                title=f"PDF Polyglot Dual-Format Structure ({poly_type} + PDF)",
                description=(
                    f"File begins with a valid {poly_type} binary header while containing a functional PDF document structure. "
                    "Polyglot files can be detonated by multiple distinct interpreters (e.g. executed as an archive or binary, "
                    "or opened as a PDF), completely confusing file validation filters and sandboxes."
                ),
                details={"polyglot_header": poly_type, "mitre_technique": "T1036"}
            ))

        # 28. PDF Incremental Shadow Attack (Hide-and-Replace / Hide-and-Overlay)
        eof_count = len(re.findall(r'%%EOF', raw_text))
        if eof_count > 1 and (re.search(r'(?i)/Perms\b', raw_text) or re.search(r'(?i)/Sig\b', raw_text)):
            # Check if incremental update overrides catalog or dictionary objects
            xref_offsets = [m.start() for m in re.finditer(r'xref\b', raw_text)]
            if len(xref_offsets) > 1:
                findings.append(Finding(
                    category="exploit",
                    severity="high",
                    title="PDF Incremental Shadow Attack Indicator (Signed Document Manipulation)",
                    description=(
                        f"Document features {len(xref_offsets)} xref revision tables and digital signature (/Sig) / permissions (/Perms) markers. "
                        "Incremental shadow attacks exploit signature validation loopholes by modifying underlying content objects without invalidating existing cryptographic signatures."
                    ),
                    details={"revision_count": len(xref_offsets), "mitre_technique": "T1565.001"}
                ))

        # 29. Foxit Reader launchURL Arbitrary Command Execution (CVE-2023-38836)
        if re.search(r'(?i)app\.launchURL\s*\(\s*["\'](?:cmd|powershell|ms-msdt|file|cscript|wscript|\\\\)', raw_text):
            findings.append(Finding(
                category="exploit",
                severity="critical",
                title="Foxit Reader Arbitrary Command Execution via launchURL (CVE-2023-38836)",
                description=(
                    "JavaScript invokes app.launchURL() with protocol handlers (cmd:, powershell:, ms-msdt:, or UNC paths). "
                    "Exploits CVE-2023-38836 to bypass URL scheme restrictions and trigger external process execution in Foxit Reader."
                ),
                details={"cve": "CVE-2023-38836", "mitre_technique": "T1204"}
            ))

        return findings
