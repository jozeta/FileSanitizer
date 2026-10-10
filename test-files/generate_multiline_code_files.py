#!/usr/bin/env python3
"""
Generator for test files with multiline scripts:
1. word_macro_20_rows.docm: Word document with a VBA macro having >= 20 rows of code.
2. pdf_javascript_20_rows.pdf: PDF document with an embedded JavaScript script having >= 20 rows of code.
"""

import zipfile
from pathlib import Path
import fitz

BASE_DIR = Path(__file__).parent.resolve()

def generate_word_macro_20_rows():
    file_path = BASE_DIR / "word_macro_20_rows.docm"

    vba_code = (
        "Attribute VB_Name = \"AuditAutomation\"\n"
        "Sub AutoOpen()\n"
        "    ' FileSanitizer Audit & Automation Module\n"
        "    ' This macro automatically executes upon opening the document\n"
        "    Dim reportTitle As String\n"
        "    Dim executionDate As String\n"
        "    Dim totalWords As Long\n"
        "    Dim totalParagraphs As Long\n"
        "    Dim statusFlag As Boolean\n"
        "    \n"
        "    reportTitle = \"Quarterly Compliance & Audit Digest\"\n"
        "    executionDate = Format(Now, \"yyyy-mm-dd hh:nn:ss\")\n"
        "    totalWords = 0\n"
        "    totalParagraphs = 14\n"
        "    statusFlag = True\n"
        "    \n"
        "    Dim sectionIndex As Integer\n"
        "    For sectionIndex = 1 To 5\n"
        "        totalWords = totalWords + (sectionIndex * 120)\n"
        "        Debug.Print \"Processing Section \" & sectionIndex & \": Current word aggregate = \" & totalWords\n"
        "    Next sectionIndex\n"
        "    \n"
        "    Dim summaryMessage As String\n"
        "    summaryMessage = FormatAuditSummary(reportTitle, totalWords, executionDate)\n"
        "    MsgBox summaryMessage, vbInformation, \"Document Automation Summary\"\n"
        "End Sub\n"
        "\n"
        "Function FormatAuditSummary(title As String, wordCount As Long, ts As String) As String\n"
        "    Dim headerLine As String\n"
        "    headerLine = \"=== \" & title & \" ===\"\n"
        "    Dim detailsLine As String\n"
        "    detailsLine = \"Audited Word Count: \" & wordCount & \" words | Generated: \" & ts\n"
        "    FormatAuditSummary = headerLine & vbCrLf & detailsLine\n"
        "End Function\n"
    )

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
            '  <Relationship Id="rIdLink1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://www.google.com" TargetMode="External"/>\n'
            '</Relationships>'
        ))

        # word/document.xml
        zf.writestr("word/document.xml", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">\n'
            '  <w:body>\n'
            '    <w:p>\n'
            '      <w:r><w:rPr><w:b/><w:sz w:val="32"/></w:rPr><w:t>Automated Macro Compliance Verification Document</w:t></w:r>\n'
            '    </w:p>\n'
            '    <w:p>\n'
            '      <w:r><w:t>This Word macro document contains an embedded Visual Basic for Applications (VBA) module with over 20 lines of automation code.</w:t></w:r>\n'
            '    </w:p>\n'
            '    <w:p>\n'
            '      <w:hyperlink r:id="rIdLink1">\n'
            '        <w:r><w:rPr><w:color w:val="1A73E8"/><w:u w:val="single"/></w:rPr><w:t>External Verification Portal: https://www.google.com</w:t></w:r>\n'
            '      </w:hyperlink>\n'
            '    </w:p>\n'
            '  </w:body>\n'
            '</w:document>'
        ))

        # word/vbaProject.bin
        # Standard OLE Compound magic header + VBA code stream
        ole_header = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" + b"\x00" * 40
        zf.writestr("word/vbaProject.bin", ole_header + vba_code.encode("latin-1"))

        # docProps/core.xml
        zf.writestr("docProps/core.xml", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/">\n'
            '  <dc:title>Automated Audit Report (20+ Rows VBA Macro)</dc:title>\n'
            '  <dc:creator>Enterprise Audit System</dc:creator>\n'
            '  <dc:description>Document automation module with multiline VBA procedure</dc:description>\n'
            '  <cp:keywords>macro, vba, audit, automation</cp:keywords>\n'
            '</cp:coreProperties>'
        ))

    print(f"Generated: {file_path.name} (VBA rows: {len(vba_code.strip().splitlines())})")
    return file_path


def generate_pdf_javascript_20_rows():
    file_path = BASE_DIR / "pdf_javascript_20_rows.pdf"

    js_code = (
        "// Document Verification & Calculation Diagnostics Module\n"
        "// FileSanitizer Test Payload - Multiline JavaScript Execution\n"
        "function runAuditDiagnostics() {\n"
        "    var docTitle = this.info.Title || 'Financial Audit Statement';\n"
        "    var pageCount = this.numPages;\n"
        "    var totalAmount = 0.0;\n"
        "    var taxRate = 0.125;\n"
        "    var lineItems = [1250.50, 430.00, 980.25, 2100.00, 650.75];\n"
        "    \n"
        "    console.println('>>> Initializing PDF Document Verification Script <<<');\n"
        "    console.println('Document Title: ' + docTitle);\n"
        "    console.println('Total Pages Discovered: ' + pageCount);\n"
        "    \n"
        "    for (var i = 0; i < lineItems.length; i++) {\n"
        "        var itemCost = lineItems[i];\n"
        "        var itemTax = itemCost * taxRate;\n"
        "        totalAmount += (itemCost + itemTax);\n"
        "        console.println('Item #' + (i + 1) + ': $' + itemCost.toFixed(2) + ' + Tax: $' + itemTax.toFixed(2));\n"
        "    }\n"
        "    \n"
        "    var auditTimestamp = new Date().toISOString();\n"
        "    console.println('Execution Timestamp: ' + auditTimestamp);\n"
        "    \n"
        "    var alertSummary = 'Verification complete! Processed ' + lineItems.length + ' entries.\\n' +\n"
        "                       'Aggregated Net Balance: $' + totalAmount.toFixed(2) + '\\n' +\n"
        "                       'Reference Portal: https://www.sunet.se';\n"
        "                       \n"
        "    app.alert({\n"
        "        cMsg: alertSummary,\n"
        "        cTitle: 'PDF Verification Script Output',\n"
        "        nIcon: 3,\n"
        "        nType: 0\n"
        "    });\n"
        "}\n"
        "\n"
        "// Automatically execute diagnostics upon opening document\n"
        "runAuditDiagnostics();\n"
    )

    doc = fitz.open()
    page = doc.new_page(width=595, height=842)

    page.insert_text(
        (50, 60),
        "FINANCIAL AUDIT STATEMENT & DIAGNOSTIC REPORT\n\n"
        "Security & Integrity Verification Document\n"
        "This PDF document contains an embedded JavaScript script with > 20 rows of code.\n\n"
        "Document Properties:\n"
        "- Embedded Script Engine: Acrobat JavaScript API\n"
        "- Script Type: Document OpenAction & Calculation Module\n"
        "- Reference URL: https://www.sunet.se\n",
        fontsize=12,
        color=(0.1, 0.1, 0.2)
    )

    # Clickable link annotation
    link_rect = fitz.Rect(50, 180, 440, 215)
    page.draw_rect(link_rect, color=(0.12, 0.35, 0.75), width=1.5, fill=(0.95, 0.97, 1.0))
    page.insert_text(
        (60, 202),
        ">> Click to Open SUNET Reference Portal (www.sunet.se) <<",
        fontsize=11,
        color=(0.08, 0.28, 0.65)
    )
    page.insert_link({
        "kind": fitz.LINK_URI,
        "from": link_rect,
        "uri": "https://www.sunet.se"
    })

    doc.set_metadata({
        "title": "Financial Audit Statement (20+ Rows JavaScript)",
        "author": "Financial Systems NOC (https://www.sunet.se)",
        "subject": "Automated PDF Script Verification",
        "keywords": "javascript, audit, calculation, https://www.sunet.se",
        "creator": "PDF Document Generator",
        "producer": "FileSanitizer Script Testing Engine"
    })

    # Create stream object with /Type /JavaScript /S /JavaScript so DidierPDFAnalyzer extracts it completely
    js_stream_xref = doc.get_new_xref()
    doc.update_object(js_stream_xref, "<</Type /JavaScript /S /JavaScript>>")
    doc.update_stream(js_stream_xref, js_code.encode("utf-8"))

    # Create an Action object pointing to the JS stream
    action_xref = doc.get_new_xref()
    doc.update_object(action_xref, f"<</Type /Action /S /JavaScript /JS {js_stream_xref} 0 R>>")

    # Set /OpenAction in Catalog
    catalog_xref = doc.pdf_catalog()
    doc.xref_set_key(catalog_xref, "OpenAction", f"{action_xref} 0 R")

    doc.save(str(file_path))
    doc.close()

    print(f"Generated: {file_path.name} (JS rows: {len(js_code.strip().splitlines())})")
    return file_path


if __name__ == "__main__":
    generate_word_macro_20_rows()
    generate_pdf_javascript_20_rows()
