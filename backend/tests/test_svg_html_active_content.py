import pytest
from app.analyzers.active_content import ActiveContentAnalyzer
from app.sanitizers.svg_sanitizer import SVGSanitizer
from app.sanitizers.html_sanitizer import HTMLSanitizer
from app.sanitizers.base import SanitizationOptions

def test_svg_script_detection_and_rasterization(temp_dir):
    svg_path = temp_dir / "exploit.svg"
    svg_content = """<?xml version="1.0" standalone="no"?>
    <svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
        <circle cx="100" cy="100" r="50" fill="red" onload="alert(document.cookie)"/>
        <script type="text/javascript">
            window.location = "http://attacker.com/steal";
        </script>
    </svg>"""
    svg_path.write_text(svg_content)

    analyzer = ActiveContentAnalyzer()
    res = analyzer.analyze(svg_path, svg_path.name, "image/svg+xml")

    assert res.data["has_javascript"] is True
    assert res.data["has_event_handlers"] is True

    # Test Rasterization CDR (Maximum Sanitization)
    clean_path = temp_dir / "clean_svg_rasterized.png"
    sanitizer = SVGSanitizer()
    opts = SanitizationOptions(profile="maximum", rasterize_pages=True)

    clean_res = sanitizer.sanitize(svg_path, clean_path, opts, svg_path.name)
    assert clean_res.success is True
    assert clean_res.target_extension == "png"
    assert clean_res.output_path.exists()

def test_html_sanitizer_removes_scripts_and_iframes(temp_dir):
    html_path = temp_dir / "phish.html"
    raw_html = """<!DOCTYPE html>
    <html>
        <body>
            <h1>Sign in</h1>
            <iframe src="http://evil.com/fake_login"></iframe>
            <script>document.write('XSS');</script>
            <p onclick="steal()">Click here</p>
        </body>
    </html>"""
    html_path.write_text(raw_html)

    clean_path = temp_dir / "clean.html"
    sanitizer = HTMLSanitizer()
    opts = SanitizationOptions(profile="security")

    res = sanitizer.sanitize(html_path, clean_path, opts, html_path.name)
    assert res.success is True

    clean_content = clean_path.read_text()
    assert "<script" not in clean_content
    assert "<iframe" not in clean_content
    assert "onclick" not in clean_content
