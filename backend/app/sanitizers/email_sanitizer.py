import email
from email import policy
from email.message import EmailMessage
from pathlib import Path
from typing import Dict, Any, List, Optional
from bs4 import BeautifulSoup
import re

from app.sanitizers.base import BaseSanitizer, SanitizationOptions, SanitizationResult
from app.core.logging_config import logger

DANGEROUS_EXTS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js",
    ".jse", ".wsf", ".wsh", ".hta", ".cpl", ".pif", ".jar", ".msi",
    ".dll", ".com", ".gadget", ".iso", ".img", ".vhd", ".lnk"
}

class EmailSanitizer(BaseSanitizer):
    @property
    def name(self) -> str:
        return "EmailSanitizer"

    def sanitize(
        self,
        input_path: Path,
        output_path: Path,
        options: SanitizationOptions,
        original_filename: str = ""
    ) -> SanitizationResult:
        removed_items = []
        original_size = input_path.stat().st_size

        try:
            with open(input_path, "rb") as f:
                raw_bytes = f.read()
            msg = email.message_from_bytes(raw_bytes, policy=policy.default)
        except Exception as e:
            return SanitizationResult(
                success=False,
                output_path=output_path,
                sanitized_filename=f"sanitized_{original_filename}" if original_filename else output_path.name,
                target_extension=".eml",
                warnings=[f"Failed to parse email for sanitization: {e}"],
                details={"original_size": original_size}
            )

        # Create fresh, clean email message
        clean_msg = EmailMessage()

        # Copy essential headers
        for h in ["From", "To", "Cc", "Bcc", "Subject", "Date", "Message-ID"]:
            val = msg.get(h)
            if val:
                clean_msg[h] = str(val)

        clean_msg["X-Sanitized-By"] = "FileSanitizer Enterprise CDR"

        # Sanitize body
        body_plain = ""
        body_html = ""

        try:
            body_part = msg.get_body(preferencelist=('plain',))
            if body_part:
                body_plain = body_part.get_content()
        except Exception:
            pass

        try:
            html_part = msg.get_body(preferencelist=('html',))
            if html_part:
                body_html = html_part.get_content()
        except Exception:
            pass

        # If get_body didn't find parts, walk
        if not body_plain and not body_html:
            for part in msg.walk():
                ctype = part.get_content_type()
                if ctype == "text/plain" and not body_plain:
                    try:
                        body_plain = part.get_content()
                    except Exception:
                        pass
                elif ctype == "text/html" and not body_html:
                    try:
                        body_html = part.get_content()
                    except Exception:
                        pass

        # Sanitize HTML body: remove tracking pixels, scripts, iframes
        if body_html:
            soup = BeautifulSoup(body_html, 'html.parser')

            # 1. Remove tracking pixels
            for img in soup.find_all('img'):
                src = img.get('src', '')
                width = str(img.get('width', '')).strip().lower()
                height = str(img.get('height', '')).strip().lower()
                style = str(img.get('style', '')).strip().lower()

                is_tracking = (
                    width in ['0', '1', '0px', '1px'] and height in ['0', '1', '0px', '1px']
                    or 'display:none' in style or 'visibility:hidden' in style
                    or any(pat in src.lower() for pat in ['pixel.gif', 'beacon', 'track', 'open.php', 'wf.gif', 'trk'])
                )
                if is_tracking:
                    img.decompose()
                    removed_items.append(f"Tracking Pixel / Web Beacon ({src[:40]}...)")

            # 2. Remove script, object, embed, iframe tags
            for dangerous_tag in soup.find_all(['script', 'object', 'embed', 'iframe', 'form']):
                removed_items.append(f"Active HTML element: <{dangerous_tag.name}>")
                dangerous_tag.decompose()

            # 3. Clean inline event handlers (onload, onclick, etc.)
            for tag in soup.find_all(True):
                attrs_to_remove = [attr for attr in tag.attrs if attr.lower().startswith('on')]
                for attr in attrs_to_remove:
                    del tag.attrs[attr]
                    removed_items.append(f"Inline DOM event handler: {attr}")

            clean_html = str(soup)
            clean_msg.set_content(body_plain or "This email was sanitized by FileSanitizer.")
            clean_msg.add_alternative(clean_html, subtype='html')
        elif body_plain:
            clean_msg.set_content(body_plain)
        else:
            clean_msg.set_content("(No message body)")

        # Sanitize Attachments
        for part in msg.iter_attachments():
            att_name = part.get_filename() or "unnamed_attachment"
            ext = Path(att_name).suffix.lower()
            try:
                att_payload = part.get_payload(decode=True) or b""
            except Exception:
                att_payload = b""

            if ext in DANGEROUS_EXTS:
                # Disarm executable attachment by replacing with quarantine notification
                quarantine_note = (
                    f"--- SECURITY WARNING: ATTACHMENT QUARANTINED ---\n"
                    f"Original Filename: {att_name}\n"
                    f"File Type: {part.get_content_type()} ({ext})\n"
                    f"Action: Disarmed by FileSanitizer CDR Policy.\n"
                    f"Reason: Dangerous executable file formats are prohibited in message bodies.\n"
                ).encode('utf-8')
                clean_msg.add_attachment(
                    quarantine_note,
                    maintype='text',
                    subtype='plain',
                    filename=f"{att_name}.QUARANTINED.txt"
                )
                removed_items.append(f"Dangerous Attachment Neutralized: {att_name}")
            else:
                # Preserve non-executable attachments
                maintype = part.get_content_maintype()
                subtype = part.get_content_subtype()
                clean_msg.add_attachment(
                    att_payload,
                    maintype=maintype,
                    subtype=subtype,
                    filename=att_name
                )

        # If requested, convert clean email into a secure static PDF document
        if options.convert_to_pdf or output_path.suffix.lower() == ".pdf":
            try:
                import fitz
                pdf_path = output_path.with_suffix(".pdf")
                doc = fitz.open()
                page = doc.new_page(width=595, height=842)
                page.insert_text((50, 45), "FileSanitizer Enterprise - Sanitized Email Document", fontsize=12, fontname="helv", color=(0.2, 0.4, 0.8))
                page.draw_line((50, 55), (545, 55), color=(0.8, 0.8, 0.8), width=1)
                y = 80
                headers_to_show = [
                    ("Subject", clean_msg.get("Subject", "(No Subject)")),
                    ("From", clean_msg.get("From", "Unknown")),
                    ("To", clean_msg.get("To", "Unknown")),
                    ("Date", clean_msg.get("Date", "Unknown")),
                ]
                for h_label, h_val in headers_to_show:
                    page.insert_text((50, y), f"{h_label}:", fontsize=9, fontname="helv-bold", color=(0.3, 0.3, 0.3))
                    page.insert_text((110, y), str(h_val)[:80], fontsize=9, fontname="helv", color=(0.1, 0.1, 0.1))
                    y += 18
                page.draw_line((50, y), (545, y), color=(0.85, 0.85, 0.85), width=0.5)
                y += 22

                display_text = body_plain or (BeautifulSoup(body_html, 'html.parser').get_text() if body_html else "(No message body)")
                for line in display_text.splitlines()[:250]:
                    if y > 800:
                        page = doc.new_page(width=595, height=842)
                        y = 50
                    page.insert_text((50, y), line[:95], fontsize=9, fontname="courier", color=(0.15, 0.15, 0.15))
                    y += 14
                doc.save(str(pdf_path), garbage=4, deflate=True)
                doc.close()

                base_name = original_filename.rsplit(".", 1)[0] if original_filename else "email"
                removed_items.append("Converted email message into safe, static PDF document")
                sanitized_size = pdf_path.stat().st_size
                return SanitizationResult(
                    success=True,
                    output_path=pdf_path,
                    sanitized_filename=f"{base_name}_sanitized.pdf",
                    target_extension=".pdf",
                    removed_items=removed_items,
                    warnings=[],
                    details={
                        "original_size": original_size,
                        "sanitized_size": sanitized_size,
                        "tracking_pixels_stripped": sum(1 for item in removed_items if "Tracking Pixel" in item),
                        "active_elements_stripped": sum(1 for item in removed_items if "Active HTML" in item or "Inline DOM" in item),
                        "attachments_quarantined": sum(1 for item in removed_items if "Neutralized" in item)
                    }
                )
            except Exception as pe:
                logger.error(f"Email PDF conversion failed: {pe}")
                warnings.append(f"PDF export failed, fell back to safe .eml: {pe}")

        # Write clean sanitized EML
        try:
            with open(output_path, "wb") as f:
                f.write(clean_msg.as_bytes())
        except Exception as e:
            return SanitizationResult(
                success=False,
                output_path=output_path,
                sanitized_filename=f"sanitized_{original_filename}" if original_filename else output_path.name,
                target_extension=".eml",
                warnings=[f"Failed to write sanitized email: {e}"],
                details={"original_size": original_size}
            )

        sanitized_size = output_path.stat().st_size
        return SanitizationResult(
            success=True,
            output_path=output_path,
            sanitized_filename=f"sanitized_{original_filename}" if original_filename else output_path.name,
            target_extension=".eml",
            removed_items=removed_items,
            warnings=[],
            details={
                "original_size": original_size,
                "sanitized_size": sanitized_size,
                "tracking_pixels_stripped": sum(1 for item in removed_items if "Tracking Pixel" in item),
                "active_elements_stripped": sum(1 for item in removed_items if "Active HTML" in item or "Inline DOM" in item),
                "attachments_quarantined": sum(1 for item in removed_items if "Neutralized" in item)
            }
        )
