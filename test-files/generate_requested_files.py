import io
import zipfile
from pathlib import Path
from PIL import Image, ImageDraw
import fitz

BASE_DIR = Path(__file__).parent.resolve()

def generate_word_macro_with_google_links():
    """
    1. Word file (.docm) with a macro and links for www.google.com
    Contains:
    - word/vbaProject.bin with VBA Sub AutoOpen() macro
    - Hyperlinks to https://www.google.com and http://www.google.com in document text
    - External relationship hyperlinks in word/_rels/document.xml.rels
    - Metadata links in docProps/core.xml
    """
    file_path = BASE_DIR / "word_macro_with_google_links.docm"
    with zipfile.ZipFile(file_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        # [Content_Types].xml
        zf.writestr("[Content_Types].xml", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">\n'
            '  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>\n'
            '  <Default Extension="xml" ContentType="application/xml"/>\n'
            '  <Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/>\n'
            '  <Override PartName="/word/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/>\n'
            '  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>\n'
            '</Types>'
        ))

        # _rels/.rels
        zf.writestr("_rels/.rels", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
            '  <Relationship Id="rIdDoc" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>\n'
            '  <Relationship Id="rIdCore" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>\n'
            '</Relationships>'
        ))

        # word/_rels/document.xml.rels
        zf.writestr("word/_rels/document.xml.rels", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
            '  <Relationship Id="rIdVba" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"/>\n'
            '  <Relationship Id="rIdGoogle1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://www.google.com" TargetMode="External"/>\n'
            '  <Relationship Id="rIdGoogle2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="http://www.google.com/search?q=FileSanitizer" TargetMode="External"/>\n'
            '</Relationships>'
        ))

        # word/document.xml
        zf.writestr("word/document.xml", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">\n'
            '  <w:body>\n'
            '    <w:p>\n'
            '      <w:r><w:rPr><w:b/><w:sz w:val="32"/></w:rPr><w:t>Quarterly Search Engine Integration Report</w:t></w:r>\n'
            '    </w:p>\n'
            '    <w:p>\n'
            '      <w:r><w:t>This document demonstrates macro-enabled automation and external search engine links.</w:t></w:r>\n'
            '    </w:p>\n'
            '    <w:p>\n'
            '      <w:r><w:t>Main search portal reference: https://www.google.com</w:t></w:r>\n'
            '    </w:p>\n'
            '    <w:p>\n'
            '      <w:hyperlink r:id="rIdGoogle1">\n'
            '        <w:r><w:rPr><w:color w:val="1A73E8"/><w:u w:val="single"/></w:rPr><w:t>Click here to open www.google.com</w:t></w:r>\n'
            '      </w:hyperlink>\n'
            '    </w:p>\n'
            '    <w:p>\n'
            '      <w:hyperlink r:id="rIdGoogle2">\n'
            '        <w:r><w:rPr><w:color w:val="1A73E8"/><w:u w:val="single"/></w:rPr><w:t>Search FileSanitizer on Google: http://www.google.com/search?q=FileSanitizer</w:t></w:r>\n'
            '      </w:hyperlink>\n'
            '    </w:p>\n'
            '    <w:p>\n'
            '      <w:r><w:t>Notice: Automated metrics calculation is executed via embedded Visual Basic for Applications (VBA) macro.</w:t></w:r>\n'
            '    </w:p>\n'
            '  </w:body>\n'
            '</w:document>'
        ))

        # word/vbaProject.bin
        # Standard OLE Compound magic bytes + VBA Macro Module Stream
        vba_code = (
            "Attribute VB_Name = \"Module1\"\n"
            "Sub AutoOpen()\n"
            "    ' FileSanitizer Verification Macro\n"
            "    ' Automatically triggered on document open\n"
            "    Dim targetUrl As String\n"
            "    targetUrl = \"https://www.google.com\"\n"
            "    MsgBox \"FileSanitizer Test Macro AutoOpen triggered. Target search portal: \" & targetUrl, vbInformation, \"Macro Executed\"\n"
            "End Sub\n\n"
            "Sub CalculateMetrics()\n"
            "    Dim searchEndpoint As String\n"
            "    searchEndpoint = \"https://www.google.com/search?q=FileSanitizer\"\n"
            "    Dim i As Integer, total As Integer\n"
            "    total = 0\n"
            "    For i = 1 To 10\n"
            "        total = total + i\n"
            "    Next i\n"
            "    MsgBox \"Calculated total: \" & total & \" | Reference: \" & searchEndpoint\n"
            "End Sub\n"
        )
        ole_header = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" + b"\x00" * 40
        zf.writestr("word/vbaProject.bin", ole_header + vba_code.encode("latin-1"))

        # docProps/core.xml
        zf.writestr("docProps/core.xml", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/">\n'
            '  <dc:title>Search Engine Integration Report - https://www.google.com</dc:title>\n'
            '  <dc:creator>Security Analyst (https://www.google.com)</dc:creator>\n'
            '  <dc:description>Automated report containing VBA macros and references to https://www.google.com</dc:description>\n'
            '  <cp:keywords>macro, vba, search, google, https://www.google.com</cp:keywords>\n'
            '</cp:coreProperties>'
        ))

    print(f"Generated: {file_path.name}")
    return file_path


def generate_pdf_autorun_javascript_sunet_link():
    """
    2. PDF file that contains JS code that auto runs when opens, and a link to www.sunet.se
    Contains:
    - /OpenAction pointing to JavaScript action that auto-runs upon document opening
    - Clickable PDF link annotation to https://www.sunet.se
    - Body text URL https://www.sunet.se
    - Metadata URL https://www.sunet.se
    """
    file_path = BASE_DIR / "pdf_autorun_javascript_sunet_link.pdf"
    doc = fitz.open()

    page = doc.new_page(width=595, height=842)

    # Document Header & Body Text
    page.insert_text(
        (50, 60),
        "SWEDISH UNIVERSITY COMPUTER NETWORK (SUNET) ADVISORY\n\n"
        "Security & Network Operations Center (NOC)\n"
        "This document contains automated diagnostic scripts and portal links.\n\n"
        "1. Primary Organization Portal (Body URL):\n"
        "   https://www.sunet.se\n\n"
        "2. Direct Interactive Link Annotation (Clickable below):\n",
        fontsize=12,
        color=(0.1, 0.1, 0.2)
    )

    # Clickable PDF URI link annotation
    link_rect = fitz.Rect(50, 180, 440, 215)
    page.draw_rect(link_rect, color=(0.12, 0.35, 0.75), width=1.5, fill=(0.95, 0.97, 1.0))
    page.insert_text(
        (60, 202),
        ">> Click to Open Official SUNET Portal (www.sunet.se) <<",
        fontsize=11,
        color=(0.08, 0.28, 0.65)
    )
    page.insert_link({
        "kind": fitz.LINK_URI,
        "from": link_rect,
        "uri": "https://www.sunet.se"
    })

    page.insert_text(
        (50, 260),
        "Automated Client Actions:\n"
        "When opened in compliant PDF viewers, an embedded JavaScript /OpenAction\n"
        "is configured to execute automatically.\n\n"
        "Target URL: https://www.sunet.se/services\n",
        fontsize=11,
        color=(0.2, 0.2, 0.3)
    )

    # Metadata containing www.sunet.se
    doc.set_metadata({
        "title": "SUNET Security Advisory - https://www.sunet.se",
        "author": "SUNET Engineering (https://www.sunet.se)",
        "subject": "Network Verification & https://www.sunet.se/about",
        "keywords": "sunet, sweden, research, education, https://www.sunet.se",
        "creator": "PDF AutoRun Generator v2.0",
        "producer": "FileSanitizer Test Engine - https://www.sunet.se"
    })

    doc.save(str(file_path))
    doc.close()

    # Append OpenAction and JavaScript objects into the PDF stream
    # /OpenAction with /S /JavaScript causes compliant PDF readers to run the script immediately on open
    js_payload = (
        b"\n% AutoRun JavaScript OpenAction Section\n"
        b"/OpenAction << /S /JavaScript /JS (app.alert('FileSanitizer Verification: JavaScript OpenAction auto-executed upon document open! Connected to SUNET: https://www.sunet.se');) >>\n"
        b"/JavaScript << /JS (app.alert('Secondary Document JavaScript Triggered! Portal: https://www.sunet.se');) >>\n"
        b"/AA << /O << /S /JavaScript /JS (console.println('Auto-run action: www.sunet.se');) >> >>\n"
    )
    raw = file_path.read_bytes()
    file_path.write_bytes(raw + js_payload)

    print(f"Generated: {file_path.name}")
    return file_path


def generate_pdf_with_image_containing_sunet_url():
    """
    3. PDF file that contains an image, where the image has the text http://www.sunet.se
    Contains:
    - A raster image generated via PIL with 'http://www.sunet.se' drawn onto its pixels
    - The image is embedded inside the PDF page as an image XObject
    - Image stream metadata also contains http://www.sunet.se
    """
    file_path = BASE_DIR / "pdf_with_image_containing_sunet_url.pdf"

    # Step 1: Create the raster image with Pillow
    img_width, img_height = 640, 240
    img = Image.new("RGB", (img_width, img_height), color=(248, 250, 252))
    draw = ImageDraw.Draw(img)

    # Draw border and banner styling
    draw.rectangle([(8, 8), (img_width - 8, img_height - 8)], outline=(29, 78, 216), width=3)
    draw.rectangle([(8, 8), (img_width - 8, 48)], fill=(29, 78, 216))
    draw.text((25, 20), "SWEDISH UNIVERSITY COMPUTER NETWORK - PORTAL CREDENTIAL", fill=(255, 255, 255))

    # Prominent pixel-rendered URL text
    draw.text((30, 75), "ENDPOINT ACCESS URL (IN RASTER IMAGE):", fill=(71, 85, 105))
    draw.text((30, 105), "http://www.sunet.se", fill=(220, 38, 38))
    draw.text((30, 145), "Gateway: http://www.sunet.se/infrastructure", fill=(30, 64, 175))
    draw.text((30, 185), "Security Status: Verified Research Node", fill=(22, 101, 52))

    # Save to PNG byte stream
    img_buf = io.BytesIO()
    img.save(img_buf, format="PNG")
    img_bytes = img_buf.getvalue()

    # Step 2: Create PDF and embed the image
    doc = fitz.open()
    page = doc.new_page(width=595, height=842)

    page.insert_text(
        (50, 60),
        "DOCUMENT ATTACHMENT VERIFICATION\n\n"
        "This document embeds an image asset containing graphic text.\n"
        "Below is the embedded credential & network access card:",
        fontsize=12,
        color=(0.1, 0.1, 0.2)
    )

    # Insert raster image into PDF
    img_rect = fitz.Rect(50, 120, 545, 290)
    page.insert_image(img_rect, stream=img_bytes)

    page.insert_text(
        (50, 320),
        "Analysis Notes:\n"
        "• The image above physically encodes the text 'http://www.sunet.se' in its pixel buffer.\n"
        "• FileSanitizer's CDR Flattening / Rasterization mode converts the entire document into safe pixels,\n"
        "  disarming any potential hidden steganography or malicious image streams.",
        fontsize=10,
        color=(0.3, 0.3, 0.4)
    )

    doc.set_metadata({
        "title": "Embedded Image Graphic Report - http://www.sunet.se",
        "author": "SUNET Security Forensics",
        "subject": "Image Stream Analysis & http://www.sunet.se",
        "creator": "FileSanitizer Generator",
        "producer": "PyMuPDF Document Generator"
    })

    doc.save(str(file_path))
    doc.close()

    print(f"Generated: {file_path.name}")
    return file_path

if __name__ == "__main__":
    generate_word_macro_with_google_links()
    generate_pdf_autorun_javascript_sunet_link()
    generate_pdf_with_image_containing_sunet_url()
