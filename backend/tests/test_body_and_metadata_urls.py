import pytest
import zipfile
from pathlib import Path
from PIL import Image
import fitz

from app.analyzers.pdf_analyzer import PDFAnalyzer
from app.analyzers.office_analyzer import OfficeAnalyzer
from app.analyzers.image_analyzer import ImageAnalyzer
from app.analyzers.metadata_extractor import MetadataExtractor

def test_pdf_body_and_metadata_url_extraction(temp_dir):
    pdf_path = temp_dir / "pdf_links_body_meta.pdf"
    doc = fitz.open()
    page = doc.new_page(width=595, height=842)
    
    # Body text containing a URL
    page.insert_text((50, 80), "Visit our security page: https://body-link.portal.org/login", fontsize=12)
    
    # Body clickable link annotation
    rect = fitz.Rect(50, 100, 250, 120)
    page.insert_link({
        "kind": fitz.LINK_URI,
        "from": rect,
        "uri": "https://annotation-link.secure-cloud.net/download"
    })
    
    # Metadata containing URLs in author and subject
    doc.set_metadata({
        "title": "Advisory Notice https://metadata-title.report.org/bulletin",
        "author": "Security Team (https://metadata-author.team.org/info)",
        "subject": "Reference https://metadata-subject.tracker.com/item",
        "keywords": "audit, https://metadata-keywords.tags.net/catalog"
    })
    doc.save(str(pdf_path))
    doc.close()

    analyzer = PDFAnalyzer()
    res = analyzer.analyze(pdf_path, pdf_path.name, "application/pdf")

    assert res.success is True
    urls = res.data["urls"]
    
    # Check body text URL
    assert any("body-link.portal.org" in u for u in urls)
    # Check annotation URL
    assert any("annotation-link.secure-cloud.net" in u for u in urls)
    # Check metadata URLs
    assert any("metadata-title.report.org" in u for u in urls)
    assert any("metadata-author.team.org" in u for u in urls)
    assert any("metadata-subject.tracker.com" in u for u in urls)
    assert any("metadata-keywords.tags.net" in u for u in urls)

def test_office_body_and_metadata_url_extraction(temp_dir):
    docx_path = temp_dir / "office_links_body_meta.docx"
    with zipfile.ZipFile(docx_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">\n'
            '  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>\n'
            '  <Default Extension="xml" ContentType="application/xml"/>\n'
            '  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>\n'
            '</Types>'
        ))
        # External relationship hyperlink
        zf.writestr("word/_rels/document.xml.rels", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
            '  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" '
            'Target="https://rels-hyperlink.external-partner.com/view" TargetMode="External"/>\n'
            '</Relationships>'
        ))
        # Body text with URL
        zf.writestr("word/document.xml", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">\n'
            '  <w:body>\n'
            '    <w:p><w:r><w:t>Please navigate to https://body-text.intranet-gateway.org/verify</w:t></w:r></w:p>\n'
            '  </w:body>\n'
            '</w:document>'
        ))
        # Core metadata with URLs
        zf.writestr("docProps/core.xml", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/">\n'
            '  <dc:title>Document https://metadata-title.office-doc.net/overview</dc:title>\n'
            '  <dc:creator>Creator https://metadata-creator.person.io/profile</dc:creator>\n'
            '  <dc:description>Description with https://metadata-desc.info-portal.org/item</dc:description>\n'
            '</cp:coreProperties>'
        ))

    analyzer = OfficeAnalyzer()
    res = analyzer.analyze(docx_path, docx_path.name, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")

    assert res.success is True
    urls = res.data["urls"]

    # Check body text URL
    assert any("body-text.intranet-gateway.org" in u for u in urls)
    # Check rels hyperlink URL
    assert any("rels-hyperlink.external-partner.com" in u for u in urls)
    # Check metadata URLs
    assert any("metadata-title.office-doc.net" in u for u in urls)
    assert any("metadata-creator.person.io" in u for u in urls)
    assert any("metadata-desc.info-portal.org" in u for u in urls)

def test_image_metadata_url_extraction(temp_dir):
    img_path = temp_dir / "image_metadata_links.jpg"
    img = Image.new("RGB", (300, 300), color=(100, 150, 200))
    exif = img.getexif()

    exif[0x013B] = "Photographer https://artist-portfolio.example.org/profile"
    exif[0x8298] = "Copyright 2026 https://license-terms.media-rights.org/std"
    exif[0x010E] = "Stockholm photo - telemetry: https://telemetry-analytics.tracker-server.xyz/pixel"

    img.save(img_path, format="JPEG", exif=exif)

    analyzer = ImageAnalyzer()
    res = analyzer.analyze(img_path, img_path.name, "image/jpeg")

    assert res.success is True
    urls = res.data["urls"]

    assert any("artist-portfolio.example.org" in u for u in urls)
    assert any("license-terms.media-rights.org" in u for u in urls)
    assert any("telemetry-analytics.tracker-server.xyz" in u for u in urls)
