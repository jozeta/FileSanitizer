#!/usr/bin/env python3
"""
Generator script for external API service test files:
1. pdf_virustotal_api_test.pdf         -> VirusTotal v3 REST API
2. pdf_safebrowsing_api_test.pdf       -> Google Safe Browsing API v4
3. pdf_urlhaus_api_test.pdf            -> Abuse.ch URLhaus API v1
4. image_nominatim_geocoding_test.jpg  -> OpenStreetMap Nominatim Reverse Geocoding API
5. pdf_url_screenshot_and_redirect_test.pdf -> Headless Browser Screenshot & Redirection Service
"""

import io
import math
from pathlib import Path
import fitz
from PIL import Image, ImageDraw, ImageFont
from PIL.TiffImagePlugin import IFDRational

BASE_DIR = Path(__file__).parent.resolve()

def get_font(size=14, bold=False):
    font_paths = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/System/Library/Fonts/Helvetica.ttc",
        "/Library/Fonts/Arial.ttf"
    ]
    for p in font_paths:
        if Path(p).exists():
            try:
                return ImageFont.truetype(p, size)
            except Exception:
                pass
    return ImageFont.load_default()

# ==============================================================================
# 1. VirusTotal API Test Suite PDF
# ==============================================================================
def generate_virustotal_test_pdf():
    out_path = BASE_DIR / "pdf_virustotal_api_test.pdf"
    doc = fitz.open()

    page = doc.new_page(width=595, height=842)  # A4 size

    # Header Banner
    page.draw_rect(fitz.Rect(30, 30, 565, 85), color=(0.15, 0.35, 0.75), fill=(0.95, 0.97, 1.0), width=1.5)
    page.insert_text(fitz.Point(45, 55), "VIRUSTOTAL API v3 TEST SUITE", fontsize=15, color=(0.1, 0.25, 0.6))
    page.insert_text(fitz.Point(45, 72), "Multi-Usecase Verification Benchmark for File Hash & URL Threat Intelligence", fontsize=8.5, color=(0.3, 0.3, 0.3))

    # Instructions box
    page.draw_rect(fitz.Rect(30, 95, 565, 145), color=(0.8, 0.8, 0.8), fill=(0.98, 0.98, 0.98))
    page.insert_text(fitz.Point(45, 112), "API Integration Under Test: VirusTotal REST API v3 (https://www.virustotal.com/api/v3)", fontsize=9, color=(0.1, 0.1, 0.1))
    page.insert_text(fitz.Point(45, 126), "Configuration: Enter your key in Settings > API Keys > 'VirusTotal API Key' or set VIRUSTOTAL_API_KEY in .env", fontsize=8, color=(0.3, 0.3, 0.3))
    page.insert_text(fitz.Point(45, 138), "FileSanitizer automatically queries file hashes at /files/{hash} and discovered URLs at /urls/{id}.", fontsize=8, color=(0.2, 0.4, 0.2))

    y = 165
    usecases = [
        {
            "num": "USECASE 1: KNOWN MALICIOUS URL ON VIRUSTOTAL",
            "url": "http://evil.com/payload.exe",
            "tag": "MALICIOUS",
            "tag_color": (0.8, 0.1, 0.1),
            "desc": "Verified malicious endpoint in VirusTotal database flagged by multiple security vendors.",
            "expected": "Expected Result: reputation.virus_total = 'MALICIOUS', risk = 'MALICIOUS', vendor detection count indicator.",
            "gui_link": "https://www.virustotal.com/gui/search/http%3A%2F%2Fevil.com%2Fpayload.exe"
        },
        {
            "num": "USECASE 2: SUSPICIOUS / PHISHING TEST ENDPOINT",
            "url": "http://testsafebrowsing.appspot.com/s/phishing.html",
            "tag": "SUSPICIOUS",
            "tag_color": (0.85, 0.45, 0.0),
            "desc": "Known test endpoint triggering phishing heuristics and credential harvesting detection engines.",
            "expected": "Expected Result: reputation.virus_total = 'SUSPICIOUS', risk = 'HIGH RISK', phishing warning indicator.",
            "gui_link": "https://www.virustotal.com/gui/search/http%3A%2F%2Ftestsafebrowsing.appspot.com%2Fs%2Fphishing.html"
        },
        {
            "num": "USECASE 3: BENIGN HIGH-REPUTATION DOMAIN (CLEAN)",
            "url": "https://www.virustotal.com",
            "tag": "CLEAN",
            "tag_color": (0.1, 0.6, 0.2),
            "desc": "Official VirusTotal homepage evaluated as clean by 90+ security vendors without false positives.",
            "expected": "Expected Result: reputation.virus_total = 'CLEAN', risk = 'CLEAN', zero positive detections.",
            "gui_link": "https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.virustotal.com"
        },
        {
            "num": "USECASE 4: POPULAR SEARCH & INFORMATION INFRASTRUCTURE",
            "url": "https://www.google.com",
            "tag": "CLEAN",
            "tag_color": (0.1, 0.6, 0.2),
            "desc": "Clean major web portal validating TLS certificate inspection and headless browser screenshotting.",
            "expected": "Expected Result: reputation.virus_total = 'CLEAN', TLSv1.3 valid, screenshot successfully captured.",
            "gui_link": "https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.google.com"
        }
    ]

    for uc in usecases:
        # Card outline
        page.draw_rect(fitz.Rect(30, y, 565, y + 105), color=(0.85, 0.85, 0.85), fill=(1.0, 1.0, 1.0))
        page.draw_rect(fitz.Rect(30, y, 35, y + 105), fill=(0.15, 0.35, 0.75))

        # Title & badge
        page.insert_text(fitz.Point(45, y + 18), uc["num"], fontsize=9.5, color=(0.15, 0.25, 0.5))
        page.draw_rect(fitz.Rect(480, y + 6, 555, y + 24), fill=uc["tag_color"])
        page.insert_text(fitz.Point(495, y + 18), uc["tag"], fontsize=8, color=(1.0, 1.0, 1.0))

        # Clickable URL
        url_rect = fitz.Rect(45, y + 26, 450, y + 42)
        page.insert_link({"kind": fitz.LINK_URI, "from": url_rect, "uri": uc["url"]})
        page.insert_text(fitz.Point(45, y + 38), f"URL Target: {uc['url']}", fontsize=9, color=(0.0, 0.35, 0.8))

        # Description & Expected
        page.insert_text(fitz.Point(45, y + 55), uc["desc"], fontsize=8, color=(0.25, 0.25, 0.25))
        page.insert_text(fitz.Point(45, y + 70), uc["expected"], fontsize=8, color=(0.1, 0.4, 0.1))

        # GUI link
        gui_rect = fitz.Rect(45, y + 78, 450, y + 95)
        page.insert_link({"kind": fitz.LINK_URI, "from": gui_rect, "uri": uc["gui_link"]})
        page.insert_text(fitz.Point(45, y + 90), f"VirusTotal Web Report: {uc['gui_link']}", fontsize=7.5, color=(0.4, 0.4, 0.7))

        y += 115

    # Footer note
    page.draw_rect(fitz.Rect(30, y, 565, y + 80), color=(0.85, 0.85, 0.85), fill=(0.96, 0.98, 1.0))
    page.insert_text(fitz.Point(45, y + 20), "USECASE 5: FILE HASH DIRECT LOOKUP & INTEGRATION", fontsize=9.5, color=(0.15, 0.25, 0.5))
    page.insert_text(fitz.Point(45, y + 36), "Upon upload, FileSanitizer calculates SHA-256 and MD5 hashes, then issues a query to /api/v3/files/{sha256}.", fontsize=8, color=(0.3, 0.3, 0.3))
    page.insert_text(fitz.Point(45, y + 50), "If flagged on VirusTotal, positive vendor counts are highlighted and a clickable GUI link is created in the findings.", fontsize=8, color=(0.3, 0.3, 0.3))
    page.insert_text(fitz.Point(45, y + 66), "Interactive Discovered URLs table includes direct VirusTotal search buttons for immediate analyst triage.", fontsize=8, color=(0.1, 0.4, 0.1))

    doc.set_metadata({
        "title": "VirusTotal API v3 Threat Intelligence Verification Suite",
        "author": "Security Audit Team <virustotal-audit@security-suite.org>",
        "subject": "Comprehensive benchmark file for VirusTotal file hash and URL reputation queries",
        "keywords": "virustotal, api, reputation, malware, phishing, sha256, https://www.virustotal.com",
        "creator": "FileSanitizer API Test Suite",
        "producer": "FileSanitizer Document Engine"
    })

    doc.save(str(out_path))
    doc.close()
    print(f"Generated: {out_path.name}")
    return out_path


# ==============================================================================
# 2. Google Safe Browsing API Test Suite PDF
# ==============================================================================
def generate_safebrowsing_test_pdf():
    out_path = BASE_DIR / "pdf_safebrowsing_api_test.pdf"
    doc = fitz.open()

    page = doc.new_page(width=595, height=842)

    # Header Banner
    page.draw_rect(fitz.Rect(30, 30, 565, 85), color=(0.2, 0.55, 0.3), fill=(0.95, 1.0, 0.95), width=1.5)
    page.insert_text(fitz.Point(45, 55), "GOOGLE SAFE BROWSING API v4 TEST SUITE", fontsize=15, color=(0.1, 0.45, 0.2))
    page.insert_text(fitz.Point(45, 72), "Official Google Test Endpoints for Malware, Phishing, & Unwanted Software", fontsize=8.5, color=(0.3, 0.3, 0.3))

    # Instructions box
    page.draw_rect(fitz.Rect(30, 95, 565, 145), color=(0.8, 0.8, 0.8), fill=(0.98, 0.98, 0.98))
    page.insert_text(fitz.Point(45, 112), "API Integration Under Test: Google Safe Browsing API v4 (safebrowsing.googleapis.com)", fontsize=9, color=(0.1, 0.1, 0.1))
    page.insert_text(fitz.Point(45, 126), "Configuration: Enter your key in Settings > API Keys > 'Google Safe Browsing Key' or set SAFE_BROWSING_API_KEY in .env", fontsize=8, color=(0.3, 0.3, 0.3))
    page.insert_text(fitz.Point(45, 138), "FileSanitizer queries threatMatches:find for MALWARE, SOCIAL_ENGINEERING, and UNWANTED_SOFTWARE.", fontsize=8, color=(0.1, 0.4, 0.2))

    y = 165
    usecases = [
        {
            "num": "USECASE 1: OFFICIAL SAFE BROWSING MALWARE TEST URL",
            "url": "http://testsafebrowsing.appspot.com/s/malware.html",
            "tag": "MALWARE",
            "tag_color": (0.8, 0.1, 0.1),
            "desc": "Official Google Safe Browsing test endpoint engineered to trigger the MALWARE threat classification.",
            "expected": "Expected Result: reputation.safe_browsing = 'MALICIOUS', indicator: 'Google Safe Browsing: Flagged as MALWARE'."
        },
        {
            "num": "USECASE 2: OFFICIAL SOCIAL ENGINEERING / PHISHING TEST URL",
            "url": "http://testsafebrowsing.appspot.com/s/phishing.html",
            "tag": "PHISHING",
            "tag_color": (0.85, 0.4, 0.0),
            "desc": "Official Google Safe Browsing test endpoint engineered to trigger SOCIAL_ENGINEERING (phishing).",
            "expected": "Expected Result: reputation.safe_browsing = 'MALICIOUS', indicator: 'Google Safe Browsing: Flagged as SOCIAL_ENGINEERING'."
        },
        {
            "num": "USECASE 3: OFFICIAL UNWANTED SOFTWARE TEST URL",
            "url": "http://testsafebrowsing.appspot.com/s/unwanted.html",
            "tag": "UNWANTED",
            "tag_color": (0.7, 0.2, 0.6),
            "desc": "Official Google Safe Browsing test endpoint engineered to trigger UNWANTED_SOFTWARE (PUP/adware).",
            "expected": "Expected Result: reputation.safe_browsing = 'MALICIOUS', indicator: 'Google Safe Browsing: Flagged as UNWANTED_SOFTWARE'."
        },
        {
            "num": "USECASE 4: OFFICIAL POTENTIALLY HARMFUL APPLICATION TEST URL",
            "url": "http://testsafebrowsing.appspot.com/s/harmful.html",
            "tag": "HARMFUL",
            "tag_color": (0.8, 0.1, 0.1),
            "desc": "Official Google Safe Browsing test endpoint engineered to trigger POTENTIALLY_HARMFUL_APPLICATION.",
            "expected": "Expected Result: reputation.safe_browsing = 'MALICIOUS', indicator: 'Google Safe Browsing: Flagged as POTENTIALLY_HARMFUL_APPLICATION'."
        },
        {
            "num": "USECASE 5: VERIFIED BENIGN GOOGLE INFRASTRUCTURE (CLEAN)",
            "url": "https://safebrowsing.google.com",
            "tag": "CLEAN",
            "tag_color": (0.1, 0.6, 0.2),
            "desc": "Official Google Safe Browsing information portal. Returns zero threat matches from the API.",
            "expected": "Expected Result: reputation.safe_browsing = 'CLEAN', risk = 'CLEAN', zero threat matches."
        }
    ]

    for uc in usecases:
        page.draw_rect(fitz.Rect(30, y, 565, y + 90), color=(0.85, 0.85, 0.85), fill=(1.0, 1.0, 1.0))
        page.draw_rect(fitz.Rect(30, y, 35, y + 90), fill=(0.2, 0.55, 0.3))

        page.insert_text(fitz.Point(45, y + 17), uc["num"], fontsize=9, color=(0.1, 0.35, 0.15))
        page.draw_rect(fitz.Rect(480, y + 6, 555, y + 23), fill=uc["tag_color"])
        page.insert_text(fitz.Point(490, y + 17), uc["tag"], fontsize=7.5, color=(1.0, 1.0, 1.0))

        url_rect = fitz.Rect(45, y + 24, 450, y + 40)
        page.insert_link({"kind": fitz.LINK_URI, "from": url_rect, "uri": uc["url"]})
        page.insert_text(fitz.Point(45, y + 36), f"URL Target: {uc['url']}", fontsize=8.5, color=(0.0, 0.35, 0.8))

        page.insert_text(fitz.Point(45, y + 54), uc["desc"], fontsize=7.5, color=(0.25, 0.25, 0.25))
        page.insert_text(fitz.Point(45, y + 70), uc["expected"], fontsize=8, color=(0.1, 0.4, 0.1))

        y += 100

    doc.set_metadata({
        "title": "Google Safe Browsing API v4 Test Suite",
        "author": "Security Audit Team <safebrowsing-test@security-suite.org>",
        "subject": "Comprehensive benchmark file testing Google Safe Browsing malware, phishing, and unwanted software detections",
        "keywords": "safebrowsing, google, api, malware, phishing, unwanted, https://safebrowsing.google.com",
        "creator": "FileSanitizer API Test Suite",
        "producer": "FileSanitizer Document Engine"
    })

    doc.save(str(out_path))
    doc.close()
    print(f"Generated: {out_path.name}")
    return out_path


# ==============================================================================
# 3. Abuse.ch URLhaus API Test Suite PDF
# ==============================================================================
def generate_urlhaus_test_pdf():
    out_path = BASE_DIR / "pdf_urlhaus_api_test.pdf"
    doc = fitz.open()

    page = doc.new_page(width=595, height=842)

    # Header Banner
    page.draw_rect(fitz.Rect(30, 30, 565, 85), color=(0.7, 0.25, 0.1), fill=(1.0, 0.96, 0.94), width=1.5)
    page.insert_text(fitz.Point(45, 55), "ABUSE.CH URLHAUS API TEST SUITE", fontsize=15, color=(0.6, 0.2, 0.1))
    page.insert_text(fitz.Point(45, 72), "Malware Payload Distribution & Community Threat Feed Verification Benchmark", fontsize=8.5, color=(0.3, 0.3, 0.3))

    # Instructions box
    page.draw_rect(fitz.Rect(30, 95, 565, 145), color=(0.8, 0.8, 0.8), fill=(0.98, 0.98, 0.98))
    page.insert_text(fitz.Point(45, 112), "API Integration Under Test: Abuse.ch URLhaus API v1 (https://urlhaus-api.abuse.ch/v1/url/)", fontsize=9, color=(0.1, 0.1, 0.1))
    page.insert_text(fitz.Point(45, 126), "Configuration: Enter your key in Settings > API Keys > 'URLhaus API Key' or set URLHAUS_API_KEY in .env", fontsize=8, color=(0.3, 0.3, 0.3))
    page.insert_text(fitz.Point(45, 138), "FileSanitizer posts queries to the URLhaus database, surfacing threat tags, malware families, and reporters.", fontsize=8, color=(0.4, 0.2, 0.1))

    y = 165
    usecases = [
        {
            "num": "USECASE 1: KNOWN MALWARE DISTRIBUTION PAYLOAD LINK",
            "url": "http://evil.com/payload.exe",
            "tag": "MALICIOUS",
            "tag_color": (0.8, 0.1, 0.1),
            "desc": "Active executable payload URL listed in malware databases. Exercises URLhaus API blacklist checking.",
            "expected": "Expected Result: reputation.urlhaus = 'MALICIOUS', risk = 'MALICIOUS', threat tag indicator.",
            "ref_link": "https://urlhaus.abuse.ch/browse/"
        },
        {
            "num": "USECASE 2: DIRECT SUSPICIOUS IP WITH EXECUTABLE EXTENSION",
            "url": "http://198.51.100.22/malware.exe",
            "tag": "HIGH RISK",
            "tag_color": (0.85, 0.35, 0.0),
            "desc": "Demonstrates hybrid heuristic analysis: direct public IP host address + dangerous .exe extension + URLhaus lookup.",
            "expected": "Expected Result: Heuristic flag (Dangerous extension) + URLhaus cross-reference check.",
            "ref_link": "https://urlhaus.abuse.ch/api/"
        },
        {
            "num": "USECASE 3: CLEAN DOMAIN NOT IN URLHAUS DATABASE (BENIGN)",
            "url": "https://urlhaus.abuse.ch",
            "tag": "CLEAN",
            "tag_color": (0.1, 0.6, 0.2),
            "desc": "Official Abuse.ch URLhaus project portal. Query status returns 'no_results', validating clean parsing.",
            "expected": "Expected Result: reputation.urlhaus = 'CLEAN', zero malicious records reported.",
            "ref_link": "https://urlhaus.abuse.ch"
        },
        {
            "num": "USECASE 4: PYTHON SOFTWARE FOUNDATION REPOSITORY",
            "url": "https://www.python.org",
            "tag": "CLEAN",
            "tag_color": (0.1, 0.6, 0.2),
            "desc": "Legitimate programming language distribution portal validating high-reputation domain handling.",
            "expected": "Expected Result: reputation.urlhaus = 'CLEAN', TLS certificate valid, screenshot captured.",
            "ref_link": "https://www.python.org"
        }
    ]

    for uc in usecases:
        page.draw_rect(fitz.Rect(30, y, 565, y + 105), color=(0.85, 0.85, 0.85), fill=(1.0, 1.0, 1.0))
        page.draw_rect(fitz.Rect(30, y, 35, y + 105), fill=(0.7, 0.25, 0.1))

        page.insert_text(fitz.Point(45, y + 18), uc["num"], fontsize=9.5, color=(0.5, 0.15, 0.1))
        page.draw_rect(fitz.Rect(480, y + 6, 555, y + 24), fill=uc["tag_color"])
        page.insert_text(fitz.Point(495, y + 18), uc["tag"], fontsize=8, color=(1.0, 1.0, 1.0))

        url_rect = fitz.Rect(45, y + 26, 450, y + 42)
        page.insert_link({"kind": fitz.LINK_URI, "from": url_rect, "uri": uc["url"]})
        page.insert_text(fitz.Point(45, y + 38), f"URL Target: {uc['url']}", fontsize=9, color=(0.0, 0.35, 0.8))

        page.insert_text(fitz.Point(45, y + 55), uc["desc"], fontsize=8, color=(0.25, 0.25, 0.25))
        page.insert_text(fitz.Point(45, y + 70), uc["expected"], fontsize=8, color=(0.1, 0.4, 0.1))

        ref_rect = fitz.Rect(45, y + 78, 450, y + 95)
        page.insert_link({"kind": fitz.LINK_URI, "from": ref_rect, "uri": uc["ref_link"]})
        page.insert_text(fitz.Point(45, y + 90), f"URLhaus Reference: {uc['ref_link']}", fontsize=7.5, color=(0.5, 0.3, 0.2))

        y += 115

    # Footer note
    page.draw_rect(fitz.Rect(30, y, 565, y + 80), color=(0.85, 0.85, 0.85), fill=(0.98, 0.96, 0.95))
    page.insert_text(fitz.Point(45, y + 20), "USECASE 5: THREAT INTEL TOGGLE IN SETTINGS", fontsize=9.5, color=(0.5, 0.15, 0.1))
    page.insert_text(fitz.Point(45, y + 36), "Admins can disable external threat intel lookups via Settings > External Connections > 'Allow Threat Intel Lookups'.", fontsize=8, color=(0.3, 0.3, 0.3))
    page.insert_text(fitz.Point(45, y + 50), "When disabled, URLhaus and VirusTotal external API connections are suppressed, enforcing an isolated zero-touch audit.", fontsize=8, color=(0.3, 0.3, 0.3))
    page.insert_text(fitz.Point(45, y + 66), "Internal heuristic scanners (executable extensions, raw IP checks, keywords) continue functioning autonomously.", fontsize=8, color=(0.1, 0.4, 0.1))

    doc.set_metadata({
        "title": "Abuse.ch URLhaus API Threat Intelligence Test Suite",
        "author": "Security Audit Team <urlhaus-test@security-suite.org>",
        "subject": "Benchmark file testing Abuse.ch URLhaus API malware payload distribution lookups",
        "keywords": "urlhaus, abuse.ch, malware, api, threat-intel, payload, https://urlhaus.abuse.ch",
        "creator": "FileSanitizer API Test Suite",
        "producer": "FileSanitizer Document Engine"
    })

    doc.save(str(out_path))
    doc.close()
    print(f"Generated: {out_path.name}")
    return out_path


# ==============================================================================
# 4. OpenStreetMap Nominatim Geocoding Test Image
# ==============================================================================
def generate_nominatim_test_image():
    out_path = BASE_DIR / "image_nominatim_geocoding_test.jpg"
    width, height = 1000, 700

    # Create dark navy blue background
    dark_bg = (13, 27, 42)      # #0D1B2A
    card_bg = (27, 38, 59)      # #1B263B
    gold = (244, 208, 63)       # #F4D03F
    accent_blue = (65, 90, 119) # #415A77
    light_text = (224, 225, 221)# #E0E1DD

    img = Image.new("RGB", (width, height), color=dark_bg)
    draw = ImageDraw.Draw(img)

    # Outer border
    draw.rectangle([(20, 20), (width - 20, height - 20)], outline=accent_blue, width=2)

    # Header Card
    draw.rectangle([(35, 35), (width - 35, 120)], fill=card_bg, outline=accent_blue, width=1)
    f_title = get_font(24, bold=True)
    f_sub = get_font(13, bold=False)
    draw.text((55, 48), "OPENSTREETMAP NOMINATIM GEOCODING TEST SUITE", fill=gold, font=f_title)
    draw.text((55, 85), "Reverse Geocoding Verification: Global Landmark GPS Tags & Offline Fallback Dataset", fill=light_text, font=f_sub)

    # Main Infographic Card (Eiffel Tower, Paris, France)
    draw.rectangle([(35, 135), (width - 35, 370)], fill=card_bg, outline=accent_blue, width=1)
    f_card_hdr = get_font(18, bold=True)
    f_body = get_font(14, bold=False)
    f_mono = get_font(13, bold=True)

    draw.text((55, 150), "USECASE 1: ONLINE NOMINATIM REVERSE GEOCODING (PARIS, FRANCE)", fill=gold, font=f_card_hdr)
    draw.text((55, 185), "Embedded EXIF GPS Coordinates: 48° 51' 30.13\" N, 2° 17' 40.13\" E (Eiffel Tower)", fill=light_text, font=f_mono)
    draw.text((55, 215), "Decimal Latitude: 48.858370   |   Decimal Longitude: 2.294481   |   Altitude: 35m", fill=(180, 200, 230), font=f_mono)

    draw.text((55, 250), "Online API Endpoint: https://nominatim.openstreetmap.org/reverse?lat=48.858370&lon=2.294481&format=json", fill=(100, 180, 255), font=f_sub)
    draw.text((55, 280), "Expected Online Output: City: 'Paris', Country: 'France', Source: 'openstreetmap_nominatim'", fill=(120, 230, 140), font=f_body)
    draw.text((55, 305), "Interactive UI: Renders interactive GPS Location Badge with expandable Paris hover card in Location metadata tab.", fill=light_text, font=f_body)
    draw.text((55, 330), "Policy Switch: Settings > External Connections > 'Allow Geolocation Lookups' toggles online network access.", fill=light_text, font=f_body)

    # Usecase 2 & 3 Side Cards
    # Left: Offline Fallback
    draw.rectangle([(35, 385), (485, 600)], fill=card_bg, outline=accent_blue, width=1)
    draw.text((50, 400), "USECASE 2: OFFLINE DATABASE FALLBACK", fill=gold, font=get_font(15, bold=True))
    draw.text((50, 430), "- Toggle 'Allow Geolocation Lookups' to OFF.", fill=light_text, font=f_sub)
    draw.text((50, 455), "- Upload this file in zero-network mode.", fill=light_text, font=f_sub)
    draw.text((50, 480), "- GeoResolver uses built-in Haversine nearest-", fill=light_text, font=f_sub)
    draw.text((50, 505), "  neighbor world cities dataset.", fill=light_text, font=f_sub)
    draw.text((50, 530), "- Expected: Successfully resolves to closest city", fill=(120, 230, 140), font=f_sub)
    draw.text((50, 555), "  (Paris, France) with source: offline_database.", fill=(120, 230, 140), font=f_sub)

    # Right: Camera Hardware & Privacy
    draw.rectangle([(505, 385), (width - 35, 600)], fill=card_bg, outline=accent_blue, width=1)
    draw.text((520, 400), "USECASE 3: CAMERA HARDWARE & PRIVACY", fill=gold, font=get_font(15, bold=True))
    draw.text((520, 430), "- Embedded Camera: Canon EOS R5", fill=light_text, font=f_sub)
    draw.text((520, 455), "- Lens: RF 24-70mm F2.8 L IS USM", fill=light_text, font=f_sub)
    draw.text((520, 480), "- Software: Adobe Lightroom Classic 13.2", fill=light_text, font=f_sub)
    draw.text((520, 505), "- Author: Audit Photographer <geo@audit.org>", fill=light_text, font=f_sub)
    draw.text((520, 530), "- Sanitization Test: Stripping privacy metadata", fill=(120, 230, 140), font=f_sub)
    draw.text((520, 555), "  completely purges EXIF GPS and camera tags.", fill=(120, 230, 140), font=f_sub)

    # Footer note
    draw.text((45, 630), "OpenStreetMap Nominatim API Verification Image   |   FileSanitizer Test Suite   |   Location Privacy Benchmark", fill=(130, 150, 180), font=get_font(12, bold=False))

    # --- Write High-Precision EXIF GPS Metadata ---
    exif = img.getexif()

    # Hardware & Software
    exif[0x010F] = "Canon"                                     # Make
    exif[0x0110] = "Canon EOS R5"                              # Model
    exif[0x0131] = "Adobe Photoshop Lightroom Classic 13.2"   # Software
    exif[0x013B] = "Audit Photographer <geo-privacy@security-test.org>" # Artist
    exif[0x8298] = "Copyright (c) 2026 Security Audit Team"    # Copyright
    exif[0x0132] = "2026:05:20 16:45:10"                      # DateTime

    # GPS IFD tags (Eiffel Tower: 48° 51' 30.13" N, 2° 17' 40.13" E)
    gps_ifd = exif.get_ifd(0x8825)
    gps_ifd[1] = "N"
    gps_ifd[2] = (IFDRational(48, 1), IFDRational(51, 1), IFDRational(3013, 100))
    gps_ifd[3] = "E"
    gps_ifd[4] = (IFDRational(2, 1), IFDRational(17, 1), IFDRational(4013, 100))
    gps_ifd[5] = 0  # Above sea level
    gps_ifd[6] = IFDRational(35, 1) # 35 meters altitude

    img.save(out_path, format="JPEG", exif=exif, quality=95)
    print(f"Generated: {out_path.name}")
    return out_path


# ==============================================================================
# 5. URL Screenshot & Redirect Test PDF
# ==============================================================================
def generate_screenshot_redirect_test_pdf():
    out_path = BASE_DIR / "pdf_url_screenshot_and_redirect_test.pdf"
    doc = fitz.open()

    page = doc.new_page(width=595, height=842)

    # Header Banner
    page.draw_rect(fitz.Rect(30, 30, 565, 85), color=(0.4, 0.2, 0.6), fill=(0.97, 0.95, 1.0), width=1.5)
    page.insert_text(fitz.Point(45, 55), "URL SCREENSHOT & REDIRECTION TEST SUITE", fontsize=15, color=(0.35, 0.15, 0.55))
    page.insert_text(fitz.Point(45, 72), "Headless Browser Capture, URL Shortener Unmasking, & SSRF Firewall Verification", fontsize=8.5, color=(0.3, 0.3, 0.3))

    # Instructions box
    page.draw_rect(fitz.Rect(30, 95, 565, 145), color=(0.8, 0.8, 0.8), fill=(0.98, 0.98, 0.98))
    page.insert_text(fitz.Point(45, 112), "Services Under Test: Headless Chromium Browser (browser:3000) & URL Redirection Engine", fontsize=9, color=(0.1, 0.1, 0.1))
    page.insert_text(fitz.Point(45, 126), "Configuration: Settings > External Connections > 'Allow Screenshots' and 'Allow HTTP Status & Redirects'", fontsize=8, color=(0.3, 0.3, 0.3))
    page.insert_text(fitz.Point(45, 138), "Features tested: Full-page website capture, shortener destination unmasking, SSRF blocking, modal zoom.", fontsize=8, color=(0.35, 0.15, 0.55))

    y = 165
    usecases = [
        {
            "num": "USECASE 1: URL SHORTENER UNMASKING & TARGET SCREENSHOT",
            "url": "https://shorturl.at/CT7su",
            "tag": "SHORTENER",
            "tag_color": (0.4, 0.2, 0.6),
            "desc": "Masked shortlink targeting Swedish University Network. Follows 301/302 redirect and captures screenshot of destination.",
            "expected": "Expected: is_shortener = true, redirect_url = 'https://www.sunet.se', captured screenshot of SUNET portal."
        },
        {
            "num": "USECASE 2: DIRECT MAJOR HTTPS SITE (CLICK-TO-ENLARGE MODAL)",
            "url": "https://www.wikipedia.org",
            "tag": "BROWSER OK",
            "tag_color": (0.1, 0.6, 0.2),
            "desc": "Global encyclopedia portal. Renders thumbnail in Discovered URLs; clicking thumbnail opens full lightbox modal.",
            "expected": "Expected: HTTP 200, TLSv1.3 valid, screenshot_available = true, click-to-enlarge modal functional."
        },
        {
            "num": "USECASE 3: SSRF FIREWALL PROTECTION (PRIVATE NETWORK BLOCKED)",
            "url": "http://192.168.1.1:8080/admin",
            "tag": "SSRF BLOCKED",
            "tag_color": (0.8, 0.1, 0.1),
            "desc": "Internal RFC-1918 private network endpoint. FileSanitizer's SSRF firewall blocks outbound connection.",
            "expected": "Expected: is_ssrf_safe = false, ssrf_reason = 'private/internal network', screenshot prohibited."
        },
        {
            "num": "USECASE 4: DANGEROUS FILE DOWNLOAD PATH HEURISTIC",
            "url": "http://evil.com/setup.exe",
            "tag": "PAYLOAD DETECTED",
            "tag_color": (0.85, 0.35, 0.0),
            "desc": "Suspicious URL with executable payload extension (.exe). Intercepted by heuristic reputation analyzer.",
            "expected": "Expected: Dangerous executable payload extension detected in URL path, elevated risk indicator."
        }
    ]

    for uc in usecases:
        page.draw_rect(fitz.Rect(30, y, 565, y + 105), color=(0.85, 0.85, 0.85), fill=(1.0, 1.0, 1.0))
        page.draw_rect(fitz.Rect(30, y, 35, y + 105), fill=(0.4, 0.2, 0.6))

        page.insert_text(fitz.Point(45, y + 18), uc["num"], fontsize=9.5, color=(0.3, 0.1, 0.45))
        page.draw_rect(fitz.Rect(460, y + 6, 555, y + 24), fill=uc["tag_color"])
        page.insert_text(fitz.Point(470, y + 18), uc["tag"], fontsize=7.5, color=(1.0, 1.0, 1.0))

        url_rect = fitz.Rect(45, y + 26, 450, y + 42)
        page.insert_link({"kind": fitz.LINK_URI, "from": url_rect, "uri": uc["url"]})
        page.insert_text(fitz.Point(45, y + 38), f"URL Target: {uc['url']}", fontsize=9, color=(0.0, 0.35, 0.8))

        page.insert_text(fitz.Point(45, y + 55), uc["desc"], fontsize=8, color=(0.25, 0.25, 0.25))
        page.insert_text(fitz.Point(45, y + 70), uc["expected"], fontsize=8, color=(0.1, 0.4, 0.1))

        y += 115

    # Footer note
    page.draw_rect(fitz.Rect(30, y, 565, y + 80), color=(0.85, 0.85, 0.85), fill=(0.97, 0.95, 1.0))
    page.insert_text(fitz.Point(45, y + 20), "USECASE 5: GRANULAR EXTERNAL TOUCH SETTINGS", fontsize=9.5, color=(0.35, 0.15, 0.55))
    page.insert_text(fitz.Point(45, y + 36), "Admins can toggle 'Allow Screenshots' and 'Allow HTTP Status & Redirects' individually under Settings.", fontsize=8, color=(0.3, 0.3, 0.3))
    page.insert_text(fitz.Point(45, y + 50), "Disabling 'Allow Screenshots' prevents headless browser execution while allowing certificate and status checks.", fontsize=8, color=(0.3, 0.3, 0.3))
    page.insert_text(fitz.Point(45, y + 66), "Disabling 'Allow All External Connections' forces 100% offline air-gapped security analysis.", fontsize=8, color=(0.1, 0.4, 0.1))

    doc.set_metadata({
        "title": "URL Screenshot & Redirection Test Suite",
        "author": "Security Audit Team <browser-test@security-suite.org>",
        "subject": "Benchmark file testing headless Chromium screenshots, URL shortener unmasking, and SSRF protection",
        "keywords": "screenshot, playwright, shorturl, redirect, ssrf, tls, https://www.wikipedia.org",
        "creator": "FileSanitizer API Test Suite",
        "producer": "FileSanitizer Document Engine"
    })

    doc.save(str(out_path))
    doc.close()
    print(f"Generated: {out_path.name}")
    return out_path


def main():
    print("Generating external API service test files...")
    generate_virustotal_test_pdf()
    generate_safebrowsing_test_pdf()
    generate_urlhaus_test_pdf()
    generate_nominatim_test_image()
    generate_screenshot_redirect_test_pdf()
    print("All external API service test files created successfully!")

if __name__ == "__main__":
    main()
