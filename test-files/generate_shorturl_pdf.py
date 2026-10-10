#!/usr/bin/env python3
"""
Generates a PDF file containing the URL shortener link: https://shorturl.at/CT7su
Embedded in:
- Document body text
- Interactive clickable PDF URI link annotation
- Document metadata (Title, Subject, Keywords, Author)
"""

from pathlib import Path
import fitz

BASE_DIR = Path(__file__).parent.resolve()

def generate_pdf_with_shorturl():
    file_path = BASE_DIR / "pdf_with_shorturl.pdf"
    target_url = "https://shorturl.at/CT7su"

    doc = fitz.open()
    page = doc.new_page(width=595, height=842)

    # Document Header & Notice
    page.insert_text(
        (50, 60),
        "DOCUMENT SECURITY INSPECTION ADVISORY\n\n"
        "Security Operations & Link Verification Test\n"
        "This document contains an external shortened URL reference.\n\n"
        "1. Discovered Body Text Link:\n"
        f"   {target_url}\n\n"
        "2. Clickable Interactive Link Annotation:\n",
        fontsize=12,
        color=(0.1, 0.1, 0.2)
    )

    # Draw styled box for clickable link annotation
    link_rect = fitz.Rect(50, 190, 480, 230)
    page.draw_rect(link_rect, color=(0.12, 0.45, 0.85), width=1.5, fill=(0.94, 0.97, 1.0))
    page.insert_text(
        (60, 214),
        f">> Click to Access Shortened Link: {target_url} <<",
        fontsize=11,
        color=(0.08, 0.3, 0.75)
    )

    # Insert clickable URI annotation
    page.insert_link({
        "kind": fitz.LINK_URI,
        "from": link_rect,
        "uri": target_url
    })

    # Additional text explaining URL shortener risks
    page.insert_text(
        (50, 270),
        "Security Analysis Context:\n"
        "- URL shortening services (e.g., shorturl.at, bit.ly, tinyurl.com) mask the ultimate\n"
        "  destination hostname and path.\n"
        "- FileSanitizer analyzes the shortener host, evaluates TLS security, tracks redirect\n"
        "  destinations, and checks threat intelligence feeds.\n\n"
        f"Primary Target Endpoint: {target_url}\n",
        fontsize=10.5,
        color=(0.25, 0.25, 0.3)
    )

    # Embed in Document Metadata
    doc.set_metadata({
        "title": f"Security Notice - Shortened Link ({target_url})",
        "author": f"Security Testing Unit ({target_url})",
        "subject": f"URL Redirection & Masking Test ({target_url})",
        "keywords": f"shorturl, redirect, security, masking, {target_url}",
        "creator": "FileSanitizer Test Generator",
        "producer": f"PDF Security Suite - {target_url}"
    })

    doc.save(str(file_path))
    doc.close()

    print(f"Generated: {file_path.name}")
    return file_path

if __name__ == "__main__":
    generate_pdf_with_shorturl()
