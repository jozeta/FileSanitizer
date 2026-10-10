#!/usr/bin/env python3
"""
Generates a multi-page PDF document containing 12 distinct real websites:
- Placed in body text
- Set up as clickable interactive PDF URI annotations
- Embedded in document metadata
"""

from pathlib import Path
import fitz

BASE_DIR = Path(__file__).parent.resolve()

REAL_SITES = [
    {
        "name": "Google Search",
        "url": "https://www.google.com",
        "category": "Search & Information Retrieval",
        "desc": "Global web search engine and internet services portal."
    },
    {
        "name": "Wikipedia The Free Encyclopedia",
        "url": "https://www.wikipedia.org",
        "category": "Reference & Encyclopedia",
        "desc": "Multilingual open-collaborative online encyclopedia maintained by Wikimedia."
    },
    {
        "name": "GitHub Development Platform",
        "url": "https://github.com",
        "category": "Software Engineering & Git",
        "desc": "Cloud repository hosting, source code management, and collaboration."
    },
    {
        "name": "Python Software Foundation",
        "url": "https://www.python.org",
        "category": "Programming Languages & Open Source",
        "desc": "Official homepage and documentation for the Python programming language."
    },
    {
        "name": "Swedish University Network (SUNET)",
        "url": "https://www.sunet.se",
        "category": "Academic & Research Network",
        "desc": "High-capacity network infrastructure connecting Swedish universities and colleges."
    },
    {
        "name": "Mozilla Foundation",
        "url": "https://www.mozilla.org",
        "category": "Browser Security & Open Web",
        "desc": "Makers of the Firefox web browser and champions of internet privacy standards."
    },
    {
        "name": "World Wide Web Consortium (W3C)",
        "url": "https://www.w3.org",
        "category": "Web Standards Organization",
        "desc": "International organization defining core technical specifications for the web."
    },
    {
        "name": "Stack Overflow Community",
        "url": "https://stackoverflow.com",
        "category": "Developer Knowledgebase",
        "desc": "Public platform and question-and-answer community for software developers."
    },
    {
        "name": "Cloudflare Global Network",
        "url": "https://www.cloudflare.com",
        "category": "Content Delivery & DDoS Protection",
        "desc": "Global cloud network provider offering DNS, CDN, and cybersecurity defenses."
    },
    {
        "name": "Electronic Frontier Foundation (EFF)",
        "url": "https://www.eff.org",
        "category": "Digital Rights & Privacy",
        "desc": "Non-profit defense organization protecting user digital civil liberties and privacy."
    },
    {
        "name": "Internet Archive & Wayback Machine",
        "url": "https://archive.org",
        "category": "Digital Library & Web Archiving",
        "desc": "Digital library preserving historical snapshots of millions of websites."
    },
    {
        "name": "CVE Program & Vulnerability List",
        "url": "https://cve.org",
        "category": "Cybersecurity Vulnerability Database",
        "desc": "The international standard for identifying and cataloging cybersecurity flaws."
    }
]

def generate_pdf_with_10_urls():
    output_path = BASE_DIR / "pdf_with_10_real_urls.pdf"

    doc = fitz.open()

    # We will generate a structured 2-page document with 6 sites per page
    items_per_page = 6
    total_pages = (len(REAL_SITES) + items_per_page - 1) // items_per_page

    for page_num in range(total_pages):
        page = doc.new_page(width=595, height=842)  # A4 size

        # Header banner
        page.draw_rect(fitz.Rect(0, 0, 595, 75), color=(0.12, 0.22, 0.4), fill=(0.95, 0.97, 1.0))
        page.insert_text(
            (40, 36),
            "VERIFIED GLOBAL WEB DIRECTORY",
            fontsize=15,
            fontname="helv",
            color=(0.1, 0.18, 0.45)
        )
        page.insert_text(
            (40, 56),
            f"Curated reference catalog containing verified real-world URLs — Page {page_num + 1} of {total_pages}",
            fontsize=9.5,
            fontname="helv",
            color=(0.35, 0.4, 0.5)
        )

        start_idx = page_num * items_per_page
        end_idx = min(start_idx + items_per_page, len(REAL_SITES))
        current_sites = REAL_SITES[start_idx:end_idx]

        y_offset = 100
        for i, site in enumerate(current_sites):
            item_num = start_idx + i + 1

            # Card container box
            card_rect = fitz.Rect(40, y_offset, 555, y_offset + 105)
            page.draw_rect(
                card_rect,
                color=(0.82, 0.86, 0.92),
                fill=(0.98, 0.99, 1.0),
                width=1
            )

            # Left accent indicator bar
            accent_rect = fitz.Rect(40, y_offset, 45, y_offset + 105)
            page.draw_rect(accent_rect, color=(0.2, 0.45, 0.9), fill=(0.25, 0.48, 0.88))

            # Number badge
            page.insert_text(
                (55, y_offset + 22),
                f"#{item_num:02d}  {site['name']}",
                fontsize=12,
                fontname="helv",
                color=(0.08, 0.15, 0.35)
            )

            # Category
            page.insert_text(
                (55, y_offset + 38),
                f"Category: {site['category']}",
                fontsize=8.5,
                fontname="helv",
                color=(0.4, 0.45, 0.55)
            )

            # Description
            page.insert_text(
                (55, y_offset + 54),
                site["desc"],
                fontsize=9,
                fontname="helv",
                color=(0.25, 0.3, 0.38)
            )

            # Clickable Button Box for URL
            btn_rect = fitz.Rect(55, y_offset + 66, 540, y_offset + 95)
            page.draw_rect(
                btn_rect,
                color=(0.2, 0.45, 0.85),
                fill=(0.92, 0.95, 1.0),
                width=1
            )

            # Button text
            page.insert_text(
                (65, y_offset + 84),
                f"↗ Visit: {site['url']}",
                fontsize=9.5,
                fontname="helv",
                color=(0.1, 0.3, 0.75)
            )

            # Insert interactive clickable URI annotation
            page.insert_link({
                "kind": fitz.LINK_URI,
                "from": btn_rect,
                "uri": site["url"]
            })

            y_offset += 118

        # Footer
        page.insert_text(
            (40, 815),
            "FileSanitizer CDR Inspection Test Document — Verified Real-World Domain Suite",
            fontsize=8,
            fontname="helv",
            color=(0.5, 0.55, 0.65)
        )

    # Embed URLs in Document Metadata
    all_urls = [s["url"] for s in REAL_SITES]
    doc.set_metadata({
        "title": "Verified Global Web Directory with 12 Real URLs",
        "author": "FileSanitizer Test Engine (https://www.google.com, https://github.com)",
        "subject": "Automated URL Discovery, Reputation Inspection, and Thumbnail Preview",
        "keywords": ", ".join(all_urls)
    })

    doc.save(str(output_path))
    doc.close()

    print(f"Generated PDF with {len(REAL_SITES)} real URLs successfully at: {output_path}")
    print(f"File size: {output_path.stat().st_size:,} bytes")
    return output_path

if __name__ == "__main__":
    generate_pdf_with_10_urls()
